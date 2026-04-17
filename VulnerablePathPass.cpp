#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/CFG.h"
#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <queue>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace llvm;

namespace
{
	struct VulnerabilityLocation
	{
		std::string function;
		unsigned line;
	};

	void dumpVulnerableBlocks(const std::set<BasicBlock *> &blocks, const Function &F)
	{
		errs() << "Vulnerable blocks in function " << F.getName() << ":\n";
		if (blocks.empty())
		{
			errs() << "  [none]\n";
			return;
		}
		for (BasicBlock *BB : blocks)
		{
			errs() << "  ";
			BB->printAsOperand(errs(), false); // печатает имя, например %if.then
			errs() << "\n";
		}
	}

	void dumpVulnerableFunctions(const std::set<Function *> &vulnFuncs)
	{
		errs() << "Vulnerable functions:\n";
		if (vulnFuncs.empty())
		{
			errs() << "  [none]\n";
			return;
		}
		for (Function *F : vulnFuncs)
		{
			errs() << "  " << F->getName() << "\n";
		}
	}

	struct VulnerablePathPass : public ModulePass
	{
		static char ID;
		std::unordered_map<std::string, std::vector<std::pair<std::string, unsigned>>> ConfigVulns;

		VulnerablePathPass() : ModulePass(ID) {}

		void loadConfig(const std::string &configPath)
		{
			std::ifstream file(configPath);
			if (!file.is_open())
				return;

			std::string line;
			std::string currentFile;
			while (std::getline(file, line))
			{
				// Пропускаем пустые строки и комментарии
				if (line.empty() || line[0] == '#')
					continue;

				if (line.rfind("[file: ", 0) == 0)
				{
					size_t end = line.find(']');
					if (end != std::string::npos)
					{
						currentFile = line.substr(7, end - 7);
					}
				}
				else if (line.rfind("function: ", 0) == 0)
				{
					std::string func = line.substr(10);
					std::getline(file, line); // следующая строка — line
					if (line.rfind("line: ", 0) == 0)
					{
						unsigned ln = std::stoul(line.substr(6));
						ConfigVulns[currentFile].emplace_back(func, ln);
					}
				}
			}
		}

		// Проверяет, содержит ли инструкция ПРЯМУЮ уязвимость
		bool isDirectlyVulnerable(Instruction &I)
		{
			// Получаем отладочную информацию
			const DebugLoc &DL = I.getDebugLoc();
			if (!DL)
				return false;

			// Получаем номер строки
			unsigned line = DL.getLine();
			if (line == 0)
				return false;

			// Получаем функцию, в которой находится инструкция
			Function *F = I.getFunction();
			if (!F)
				return false;
			StringRef funcName = F->getName();

			// Получаем имя исходного файла
			DILocation *Loc = DL.get();
			if (!Loc)
				return false;
			std::string fileName = Loc->getFilename().str();

			// Убираем путь, оставляем только имя файла (если нужно)
			// Например: "/home/user/test.c" → "test.c"
			size_t lastSlash = fileName.find_last_of("/\\");
			if (lastSlash != std::string::npos)
			{
				fileName = fileName.substr(lastSlash + 1);
			}

			// Проверяем конфигурацию
			auto it = ConfigVulns.find(fileName);
			if (it == ConfigVulns.end())
				return false;

			for (const auto &entry : it->second)
			{
				const std::string &cfgFunc = entry.first;
				unsigned cfgLine = entry.second;
				if (funcName == cfgFunc && line == cfgLine)
				{
					return true;
				}
			}
			return false;
		}

		// Собирает уязвимые функции, ИСКЛЮЧАЯ main
		std::set<Function *> collectVulnerableFunctions(Module &M)
		{
			std::set<Function *> vulnFuncs;
			for (Function &F : M)
			{
				if (F.isDeclaration())
					continue;
				if (F.getName() == "main")
					continue; // ← КЛЮЧЕВОЕ: main не может быть "уязвимой функцией"
				for (BasicBlock &BB : F)
				{
					for (Instruction &I : BB)
					{
						if (isDirectlyVulnerable(I))
						{
							vulnFuncs.insert(&F);
							break;
						}
					}
				}
			}
			return vulnFuncs;
		}


		std::set<Function*> collectDirectlyVulnerableFunctions(Module &M)
		{
			std::set<Function *> vulnFuncs;
			for (Function &F : M)
			{
				if (F.isDeclaration())
					continue;
				for (BasicBlock &BB : F)
				{
					for (Instruction &I : BB)
					{
						if (isDirectlyVulnerable(I))
						{
							vulnFuncs.insert(&F);
							break;
						}
					}
				}
			}
			return vulnFuncs;
		}

		std::set<Function *> findTransitiveCallers(Module &M, const std::set<Function *> &directVulns)
		{
			// Сначала соберём прямые вызовы
			std::unordered_map<Function *, std::set<Function *>> callers;
			for (Function &F : M)
			{
				if (F.isDeclaration())
					continue;
				for (BasicBlock &BB : F)
				{
					for (Instruction &I : BB)
					{
						if (CallInst *CI = dyn_cast<CallInst>(&I))
						{
							if (Function *Callee = CI->getCalledFunction())
							{
								if (!Callee->isDeclaration())
								{
									callers[Callee].insert(&F);
								}
							}
						}
					}
				}
			}

			// Обратный BFS от уязвимых функций
			std::set<Function *> reachable;
			std::queue<Function *> worklist;
			for (Function *F : directVulns)
			{
				reachable.insert(F);
				worklist.push(F);
			}

			while (!worklist.empty())
			{
				Function *F = worklist.front();
				worklist.pop();
				for (Function *Caller : callers[F])
				{
					if (reachable.insert(Caller).second)
					{
						worklist.push(Caller);
					}
				}
			}

			return reachable;
		}

		void dumpVulnerableBlocks(const std::set<BasicBlock *> &blocks, const Function &F)
		{
			errs() << "Vulnerable blocks in " << F.getName() << ":\n";
			for (BasicBlock *BB : blocks)
			{
				errs() << "  ";
				BB->printAsOperand(errs(), false);
				errs() << "\n";
			}
		}

		bool runOnModule(Module &M) override
		{
			loadConfig("vulnerabilities.cfg");

			auto directVulns = collectDirectlyVulnerableFunctions(M);
			if (directVulns.empty())
			{
				errs() << "No directly vulnerable functions found\n";
				return false;
			}

			auto transitiveVulns = findTransitiveCallers(M, directVulns);

			errs() << "Transitively vulnerable functions:\n";
			for (Function *F : transitiveVulns)
			{
				errs() << "  " << F->getName() << "\n";
			}

			bool changed = false;
			for (Function &F : M)
			{
				if (F.isDeclaration())
					continue;

				// Если функция ведёт к уязвимости — НЕ инструментируем
				if (transitiveVulns.count(&F))
				{
					continue;
				}

				// Иначе — заменяем ВСЕ блоки на exit(0)
				for (BasicBlock &BB : F)
				{
					BB.getInstList().clear();
					IRBuilder<> Builder(&BB);
					FunctionCallee ExitFn = M.getOrInsertFunction("exit",
																  Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
					Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
					Builder.CreateUnreachable();
					changed = true;
				}
			}

			return changed;
		}
	};
}

char VulnerablePathPass::ID = 0;

static RegisterPass<VulnerablePathPass> X(
	"vuln-path",
	"Preserve only paths leading to vulnerabilities",
	false,
	false);