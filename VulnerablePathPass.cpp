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

	// debug function
	void dumpVulnerableBlocks(const std::set<BasicBlock *> &blocks, const Function &F)
	{
		errs() << "Vulnerable blocks in " << F.getName() << ":\n";
		if (blocks.empty())
		{
			errs() << "  [none]\n";
			return;
		}
		for (BasicBlock *BB : blocks)
		{
			errs() << "  ";
			BB->printAsOperand(errs(), false);
			errs() << "\n";
		}
	}

	// debug function
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
					std::getline(file, line); // next line is "line: N"
					if (line.rfind("line: ", 0) == 0)
					{
						unsigned ln = std::stoul(line.substr(6));
						ConfigVulns[currentFile].emplace_back(func, ln);
					}
				}
			}
		}

		// Проверяет, есть ли функция в vulnerabilities.cfg
		bool isFunctionVulnerable(Function *F)
		{
			if (!F)
				return false;
			StringRef funcName = F->getName();
			for (const auto &fileEntry : ConfigVulns)
			{
				for (const auto &funcLine : fileEntry.second)
				{
					if (funcLine.first == funcName)
					{
						return true;
					}
				}
			}
			return false;
		}

		// Находит все блоки, из которых достижим вызов уязвимой функции
		std::set<BasicBlock *> findVulnerableBlocks(Function &F)
		{
			std::set<BasicBlock *> vulnerableBlocks;
			std::queue<BasicBlock *> worklist;

			// Шаг 1: найти блоки с вызовами уязвимых функций
			for (BasicBlock &BB : F)
			{
				bool hasVulnCall = false;
				for (Instruction &I : BB)
				{
					if (CallInst *CI = dyn_cast<CallInst>(&I))
					{
						if (Function *Callee = CI->getCalledFunction())
						{
							if (isFunctionVulnerable(Callee))
							{
								hasVulnCall = true;
								break;
							}
						}
					}
				}
				if (hasVulnCall)
				{
					vulnerableBlocks.insert(&BB);
					worklist.push(&BB);
				}
			}

			// Шаг 2: обратный обход — всё, что ведёт К этим блокам
			while (!worklist.empty())
			{
				BasicBlock *BB = worklist.front();
				worklist.pop();
				for (BasicBlock *Pred : predecessors(BB))
				{
					if (vulnerableBlocks.insert(Pred).second)
					{
						worklist.push(Pred);
					}
				}
			}

			return vulnerableBlocks;
		}


		bool runOnModule(Module &M) override
		{
			loadConfig("vulnerabilities.cfg");

			// Проверим, что хотя бы одна уязвимая функция указана
			bool hasVuln = false;
			for (const auto &fileEntry : ConfigVulns)
			{
				if (!fileEntry.second.empty())
				{
					hasVuln = true;
					break;
				}
			}
			if (!hasVuln)
			{
				errs() << "No vulnerable functions found in vulnerabilities.cfg\n";
				return false;
			}

			bool changed = false;

			for (Function &F : M)
			{
				if (F.isDeclaration())
					continue;

				auto vulnerableBlocks = findVulnerableBlocks(F);
				dumpVulnerableBlocks(vulnerableBlocks, F);

				for (BasicBlock &BB : F)
				{
					if (vulnerableBlocks.count(&BB))
					{
						continue; // сохраняем
					}

					// Пропускаем блоки с return/unreachable
					bool hasReturn = false;
					for (Instruction &I : BB)
					{
						if (isa<ReturnInst>(&I) || isa<UnreachableInst>(&I))
						{
							hasReturn = true;
							break;
						}
					}
					if (hasReturn)
						continue;

					// Заменяем весь блок на exit(0)
					BB.getInstList().clear();
					IRBuilder<> Builder(&BB);
					FunctionCallee ExitFn = M.getOrInsertFunction("exit",
																  Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
					Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
					Builder.CreateUnreachable();

					changed = true;
					errs() << "Replaced block with exit(0): ";
					BB.printAsOperand(errs());
					errs() << " in " << F.getName() << "\n";
				}
			}

			return changed;
		}
	};
}

char VulnerablePathPass::ID = 0;

static RegisterPass<VulnerablePathPass> X(
	"vuln-path",
	"Preserve only paths leading to vulnerabilities (block-level)",
	false,
	false);