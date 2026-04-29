#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/CFG.h"
#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <string>
#include <queue>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace llvm;

namespace
{
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
		errs() << "Dump functions list:\n";
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

		std::set<Instruction*> findVulnerableInstructions(Module &M) {
			// errs() << " find vulnurable instructions ------------- " << "\n";
			std::set<Instruction*> result;
			for (Function &F : M) {
				// errs() << "  " << F.getName() << "\n";
				if (F.isDeclaration()) continue;
				for (BasicBlock &BB : F) {
					for (Instruction &I : BB) {
						if (isDirectlyVulnerable(I)) {
							result.insert(&I);
							// errs() << "has vulnurable -> " << F.getName() << "\n";

						}
					}
				}
			}
			// errs() << " --------------------------------------- " << "\n";
			return result;
		}

		std::set<Function*> findFullPreserveSet(Module &M, const std::set<Instruction*> &vulnInstrs) {
			std::set<Function*> preserve;

			// --- Forward: всё, что вызывается из уязвимых функций ---
			std::queue<Function*> forwardQ;
			for (Instruction *I : vulnInstrs) {
				Function *F = I->getFunction();
				if (preserve.insert(F).second) {
					forwardQ.push(F);
				}
			}
			while (!forwardQ.empty()) {
				Function *F = forwardQ.front(); forwardQ.pop();
				for (BasicBlock &BB : *F) {
					for (Instruction &I : BB) {
						if (CallInst *CI = dyn_cast<CallInst>(&I)) {
							if (Function *Callee = CI->getCalledFunction()) {
								// errs() << F->getName() << "  is called from vulnurable" << "\n";
								if (Callee && !Callee->isDeclaration()) {
									if (preserve.insert(Callee).second) {
										forwardQ.push(Callee);
									}
								}
							}
						}
					}
				}
			}

			// --- Backward: всё, что вызывает уязвимые функции ---
			std::unordered_map<Function*, std::set<Function*>> callers;
			for (Function &F : M) {
				if (F.isDeclaration()) continue;
				for (BasicBlock &BB : F) {
					for (Instruction &I : BB) {
						if (CallInst *CI = dyn_cast<CallInst>(&I)) {
							if (Function *Callee = CI->getCalledFunction()) {
								if (Callee && !Callee->isDeclaration()) {
									callers[Callee].insert(&F);
								}
							}
						}
					}
				}
			}

			std::queue<Function*> backwardQ;
			for (Function *F : preserve) {
				backwardQ.push(F);
			}
			while (!backwardQ.empty()) {
				Function *F = backwardQ.front(); backwardQ.pop();
				auto it = callers.find(F);
				if (it != callers.end()) {
					for (Function *Caller : it->second) {
						if (preserve.insert(Caller).second) {
							backwardQ.push(Caller);
						}
					}
				}
			}

			return preserve;
		}

		std::set<BasicBlock*> findRelevantBlocksInFunction(
			Function &F,
			const std::set<Instruction*> &vulnInstrs,
			const std::set<Function*> &preserveFuncs) {

			std::set<BasicBlock*> relevant;
			std::queue<BasicBlock*> worklist;
			errs() << F.getName() << "\n";

			// --- Шаг 1: начальные блоки ---
			for (BasicBlock &BB : F) {
				bool isStart = false;

				// 1a. Содержит уязвимую инструкцию?
				for (Instruction &I : BB) {
					if (vulnInstrs.count(&I)) {
						isStart = true;
						break;
					}
				}

				// 1b. Вызывает сохраняемую функцию?
				if (!isStart) {
					for (Instruction &I : BB) {
						if (CallInst *CI = dyn_cast<CallInst>(&I)) {
							if (Function *Callee = CI->getCalledFunction()) {
								if (preserveFuncs.count(Callee)) {
									isStart = true;
									break;
								}
							}
						}
					}
				}

				if (isStart) {
					relevant.insert(&BB);
					worklist.push(&BB);
				}
			}

			// --- Шаг 2: обратный обход, но НЕ заходим в блоки с return/exit ---
			while (!worklist.empty()) {
				BasicBlock *BB = worklist.front();
				worklist.pop();

				// Не идём дальше, если блок завершается return/unreachable
				Instruction *TI = BB->getTerminator();
				if (TI && (isa<ReturnInst>(TI) || isa<UnreachableInst>(TI))) {
					continue;
				}

				for (BasicBlock *Pred : predecessors(BB)) {
					// Также не добавляем предшественников, если они сами терминальные
					Instruction *PTI = Pred->getTerminator();
					if (PTI && (isa<ReturnInst>(PTI) || isa<UnreachableInst>(PTI))) {
						continue;
					}
					errs() << "pred" << "\n";
					
					if (relevant.insert(Pred).second) {
						worklist.push(Pred);
					}
				}
			}

			return relevant;
		}

		// Собираем все функции, вызываемые из preserveFuncs
		std::set<Function*> findFunctionsCalledFromPreserved(
			Module &M,
			const std::set<Function*> &preserveFuncs) {
			
			std::set<Function*> calledFromPreserved;

			for (Function *F : preserveFuncs) {
				// Пропускаем объявления (должны быть определены)
				if (!F || F->isDeclaration()) continue;

				for (BasicBlock &BB : *F) {
					for (Instruction &I : BB) {
						if (CallInst *CI = dyn_cast<CallInst>(&I)) {
							if (Function *Callee = CI->getCalledFunction()) {
								if (Callee && !Callee->isDeclaration()) {
									calledFromPreserved.insert(Callee);
								}
							}
						}
					}
				}
			}

			return calledFromPreserved;
		}

		bool instrumentBlockWithExit(BasicBlock &BB, Module &M, Function &F, StringRef str = "") {
			if (isa<UnreachableInst>(BB.getTerminator())) {
				return false;
			}

			// Находим позицию для вставки: ПОСЛЕ всех PHI-нод
			Instruction *InsertPos = &*BB.getFirstNonPHI();
			// Если блок состоит ТОЛЬКО из PHI-нод — вставляем в конец
			if (InsertPos == BB.getTerminator()) {
				InsertPos = BB.getTerminator();
			}
			IRBuilder<> Builder(InsertPos);
			FunctionCallee ExitFn = M.getOrInsertFunction("exit",
				Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
			Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
			errs() << "Inserted exit(0) to" << str << F.getName() << "\n";
			return true;
		}

		bool runOnModule(Module &M) override {
			loadConfig("vulnerabilities.cfg");

			auto vulnInstrs = findVulnerableInstructions(M);
			if (vulnInstrs.empty()) {
				errs() << "No vulnerable instructions found\n";
				return false;
			}
			auto preserveFuncs = findFullPreserveSet(M, vulnInstrs);
			// auto calledFromPreserved = findFunctionsCalledFromPreserved(M, preserveFuncs);
			// dumpVulnerableFunctions(calledFromPreserved);

			errs() << "Preserving functions:\n";
			for (Function *F : preserveFuncs) {
				errs() << "  " << F->getName() << "\n";
			}

			bool changed = false;
			for (Function &F : M) {
				if (F.isDeclaration() || F.empty()) continue;

				if (preserveFuncs.count(&F)) continue;
				// if (F.getName() == "main") continue;
				
				// if (calledFromPreserved.count(&F)) { 
				// 	continue; // Функция вызывается из релевантного контекста
				// } else if (preserveFuncs.count(&F)) {
				// 	// Если в функции есть нерелевантные ветки - инструментируем их
				// 	auto relevantBlocks = findRelevantBlocksInFunction(F, vulnInstrs, preserveFuncs);
				// 	for (BasicBlock &BB : F) {
				// 		if (relevantBlocks.count(&BB)) continue;
				// 		if (instrumentBlockWithExit(BB, M, F, " bloks in ")) changed = true;
				// 	}
				// // } else if (calledFromPreserved.count(&F)) { 
				// // 	continue; // Функция вызывается из релевантного контекста
				// } else {
					// Если в функции нет нерелевантных веток - инструментируем всю функцию
					for (BasicBlock &BB : F) {
						if (instrumentBlockWithExit(BB, M, F, " ")) changed = true;
					}
				// }
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