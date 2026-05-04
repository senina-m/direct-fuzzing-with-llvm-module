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
#include <algorithm>
#include <cstdlib>
#include <map>

using namespace llvm;

namespace
{
    std::string escapeDotString(const std::string &s) {
        std::string result = s;
        size_t pos = 0;
        while ((pos = result.find("\"", pos)) != std::string::npos) {
            result.replace(pos, 1, "\\\"");
            pos += 2;
        }
        return "\"" + result + "\"";
    }

    // Helper: Получает номер строки для первой инструкции блока
    unsigned getBlockLineNumber(BasicBlock *BB) {
        for (Instruction &I : *BB) {
            const DebugLoc &DL = I.getDebugLoc();
            if (DL) return DL.getLine();
        }
        return 0;
    }

    // Helper: Проверяет, является ли блок завершающим выполнение процесса или функции
    bool isTerminatingBlock(BasicBlock *BB, bool checkReturn) {
        Instruction *Term = BB->getTerminator();
        if (checkReturn && isa<ReturnInst>(Term)) return true;
        
        for (Instruction &I : *BB) {
            if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                if (Function *F = CI->getCalledFunction()) {
                    StringRef Name = F->getName();
                    if (Name == "exit" || Name == "_exit" || Name == "abort") return true;
                }
            }
        }
        return false;
    }

    // Печатает дерево путей от блока к терминалам
    void printBlockTerminationTree(BasicBlock *StartBB, const std::string &reason) {
        unsigned line = getBlockLineNumber(StartBB);
        std::string lineStr = (line > 0) ? std::to_string(line) : "?";
        
        errs() << "\n[DEBUG-TREE] Block '" << StartBB->getName() << "' (line:" << lineStr 
               << ") in func '" << StartBB->getParent()->getName() << "' INSTRUMENTED because: " << reason << "\n";
        
        // Простой вывод первых шагов вперед
        std::queue<std::pair<BasicBlock*, int>> q;
        std::set<BasicBlock*> visited;
        q.push({StartBB, 0});
        visited.insert(StartBB);

        while (!q.empty()) {
            auto [Current, depth] = q.front(); q.pop();
            std::string indent(depth * 2, ' ');
            
            unsigned cLine = getBlockLineNumber(Current);
            std::string cLineStr = (cLine > 0) ? std::to_string(cLine) : "?";
            
            errs() << indent << "Block: " << Current->getName() << " (line:" << cLineStr << ")";
            if (isTerminatingBlock(Current, true)) errs() << " [RETURN/EXIT]";
            errs() << "\n";

            if (depth < 3) { // Ограничиваем глубину вывода
                for (auto Succ : successors(Current)) {
                    if (visited.insert(Succ).second) {
                        q.push({Succ, depth + 1});
                    }
                }
            }
        }
        errs() << "[DEBUG-TREE] End.\n\n";
    }

    struct InstrumentationPlan {
        std::set<Function*> FunctionsToWipeOut; 
        std::map<Function*, std::set<BasicBlock*>> BlocksToWipeOut; 
    };

	struct VulnerablePathPass : public ModulePass
	{
		static char ID;
		std::unordered_map<std::string, std::vector<std::pair<std::string, unsigned>>> ConfigVulns;
        std::map<Function*, std::set<BasicBlock*>> DirectlyVulnerableBlocksMap;

		VulnerablePathPass() : ModulePass(ID) {}

		void loadConfig(const std::string &configPath)
		{
			std::ifstream file(configPath);
			if (!file.is_open()) {
                errs() << "[CONFIG] Warning: Could not open vulnerabilities.cfg\n";
                return;
            }

			std::string line;
			std::string currentFile;
			while (std::getline(file, line))
			{
				if (line.empty() || line[0] == '#') continue;

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
					if (std::getline(file, line)) {
						if (line.rfind("line: ", 0) == 0)
						{
                            const char* start = line.c_str() + 6;
                            char* endptr = nullptr;
                            unsigned long ln = std::strtoul(start, &endptr, 10);
                            
                            if (endptr != start && (*endptr == '\0' || *endptr == '\n' || *endptr == '\r')) {
                                ConfigVulns[currentFile].emplace_back(func, static_cast<unsigned>(ln));
                            }
						}
					}
				}
			}
            errs() << "[CONFIG] Loaded config.\n";
		}

        void findVulnerableFunctionsAndBlocks(Module &M) {
            DirectlyVulnerableBlocksMap.clear();
            
            for (Function &F : M) {
                if (F.isDeclaration()) continue;

                std::string fileName = "";
                bool foundDebugInfo = false;

                for (BasicBlock &BB : F) {
                    for (Instruction &I : BB) {
                        const DebugLoc &DL = I.getDebugLoc();
                        if (DL) {
                            DILocation *Loc = DL.get();
                            if (Loc) {
                                fileName = Loc->getFilename().str();
                                size_t lastSlash = fileName.find_last_of("/\\");
                                if (lastSlash != std::string::npos) {
                                    fileName = fileName.substr(lastSlash + 1);
                                }
                                foundDebugInfo = true;
                                break;
                            }
                        }
                    }
                    if (foundDebugInfo) break;
                }

                if (fileName.empty()) continue;

                auto itFile = ConfigVulns.find(fileName);
                if (itFile == ConfigVulns.end()) continue;

                StringRef funcName = F.getName();
                
                for (const auto &entry : itFile->second) {
                    const std::string &cfgFunc = entry.first;
                    unsigned cfgLine = entry.second;

                    if (funcName == cfgFunc) {
                        for (BasicBlock &BB : F) {
                            for (Instruction &I : BB) {
                                const DebugLoc &DL = I.getDebugLoc();
                                if (DL && DL.getLine() == cfgLine) {
                                    DirectlyVulnerableBlocksMap[&F].insert(&BB);
                                    errs() << "[VULN] Found in " << funcName << " block " << BB.getName() << "\n";
                                }
                            }
                        }
                    }
                }
            }
        }

        // Принудительно добавляет функции с точным совпадением имени в набор HelperFunctions
        void preserveSpecificFunctions(Module &M, std::queue<Function*> &funcQueue, std::set<Function*> &funcSet, const std::vector<std::string> &funcNames, const std::string &funcSetName) {
            for (const std::string &name : funcNames) {
                Function *F = M.getFunction(name);
                if (F && !F->isDeclaration()) {
                    if (funcSet.insert(F).second) {
                        funcQueue.push(F);
                        errs() << "[FORCE-ADD] Added '" << name 
                            << "' to queue " << funcSetName << " because it was manually requested.\n";
                    } else {
                        errs() << "[FORCE-ADD] '" << name << "' is already in the set " << funcSetName << " .\n";
                    }
                } else {
                    errs() << "[FORCE-ADD] Function '" << name << "' not found or is declaration.\n";
                }
            }
        }

        // Находит блоки, которые НЕ ведут к TargetInsts
        std::set<BasicBlock*> findBlocksNotLeadingToTargets(Function *F, const std::set<Instruction*> &TargetInsts) {
            std::set<BasicBlock*> blocksLeadingToTarget;
            std::set<BasicBlock*> targetBlocks;
            
            for (Instruction *I : TargetInsts) {
                if (I->getParent()->getParent() == F) {
                    targetBlocks.insert(I->getParent());
                }
            }

            std::queue<BasicBlock*> worklist;
            std::set<BasicBlock*> visited;

            for (BasicBlock *TB : targetBlocks) {
                worklist.push(TB);
                visited.insert(TB);
                blocksLeadingToTarget.insert(TB);
            }

            while (!worklist.empty()) {
                BasicBlock *Current = worklist.front(); worklist.pop();
                for (auto Pred : predecessors(Current)) {
                    if (visited.insert(Pred).second) {
                        blocksLeadingToTarget.insert(Pred);
                        worklist.push(Pred);
                    }
                }
            }

            std::set<BasicBlock*> result;
            for (BasicBlock &BB : *F) {
                if (blocksLeadingToTarget.count(&BB) == 0) {
                    result.insert(&BB);
                }
            }
            return result;
        }

        std::set<BasicBlock*> getReachableBlocks(BasicBlock *StartBlock, bool Direction) {
            std::set<BasicBlock*> reachable;
            std::queue<BasicBlock*> worklist;
            
            worklist.push(StartBlock);
            reachable.insert(StartBlock);

            while (!worklist.empty()) {
                BasicBlock *Current = worklist.front();
                worklist.pop();

                if (Direction) {
                    // Forward: идем по successor'ам
                    for (auto Succ : successors(Current)) {
                        if (reachable.insert(Succ).second) {
                            worklist.push(Succ);
                        }
                    }
                } else {
                    // Backward: идем по predecessor'ам
                    for (auto Pred : predecessors(Current)) {
                        if (reachable.insert(Pred).second) {
                            worklist.push(Pred);
                        }
                    }
                }
            }
            return reachable;
        }

        InstrumentationPlan buildInstrumentationPlan(Module &M) {
            InstrumentationPlan plan;
            
            std::set<Function*> StackFunctions;
            std::set<Function*> HelperFunctions;

            // 1. Строим граф вызовов
            std::unordered_map<Function*, std::set<Function*>> callersMap;
            std::unordered_map<Function*, std::set<Function*>> calleesMap;

            for (Function &F : M) {
                if (F.isDeclaration()) continue;
                for (BasicBlock &BB : F) {
                    for (Instruction &I : BB) {
                        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                            if (Function *Callee = CI->getCalledFunction()) {
                                if (!Callee->isDeclaration()) {
                                    callersMap[Callee].insert(&F);
                                    calleesMap[&F].insert(Callee);
                                }
                            }
                        }
                    }
                }
            }

            // 2. Построение STACK FUNCTIONS (Backward Search от уязвимости)
            // Это строгий путь вызовов К уязвимости.
            std::queue<Function*> stackQueue;
            for (auto &Pair : DirectlyVulnerableBlocksMap) {
                Function *F = Pair.first;
                if (StackFunctions.insert(F).second) {
                    stackQueue.push(F);
                    errs() << "[STACK-INIT] Added vulnerable function: " << F->getName() << "\n";
                }
            }

            while (!stackQueue.empty()) {
                Function *Curr = stackQueue.front(); stackQueue.pop();
                
                // Идем только НАЗАД (кто вызывает Curr?)
                if (callersMap.count(Curr)) {
                    for (Function *Caller : callersMap[Curr]) {
                        if (StackFunctions.insert(Caller).second) {
                            stackQueue.push(Caller);
                            errs() << "[STACK-BACK] Added caller: " << Caller->getName() << " -> " << Curr->getName() << "\n";
                        }
                    }
                }
            }

            // 3. Построение HELPER FUNCTIONS (Forward Search от стека)
            // Это функции, которые вызываются из стека, но не являются его частью.
            std::queue<Function*> helperQueue;
            
            // Инициализируем очередь всеми функциями стека
            for (Function *F : StackFunctions) {
                helperQueue.push(F);
            }
            preserveSpecificFunctions(M, helperQueue, HelperFunctions, {
                "xmlInitParserInternal",
                "xmlPosixStrdup",
                "xmlMemRead",
                "xmlSAX2SetDocumentLocator",
                "endOfInput",
                "xmlSAX2StartDocument",
                "xmlSAX2StartElementNs",
                "xmlSAX2EndElementNs",
                "xmlSAX2EndDocument",
                "xmlMemClose"},
                "Helper");

            while (!helperQueue.empty()) {
                Function *Curr = helperQueue.front(); helperQueue.pop();
                
                // Идем ВПЕРЕД (кого вызывает Curr?)
                if (calleesMap.count(Curr)) {
                    for (Function *Callee : calleesMap[Curr]) {
                        // Если вызываемая функция УЖЕ в стеке, она не хелпер, пропускаем
                        if (StackFunctions.count(Callee)) continue;
                        
                        // Если вызываемая функция еще не известна как хелпер, добавляем
                        if (HelperFunctions.insert(Callee).second) {
                            helperQueue.push(Callee);
                            errs() << "[HELPER-FWD] Added helper: " << Callee->getName() << " (called by " << Curr->getName() << ")\n";
                        }
                    }
                }
            }

            // 4. Формирование плана инструментации
            
            // --- Обработка STACK функций ---
            for (Function *F : StackFunctions) {
                if (F->isDeclaration() || F->empty()) continue;

                Instruction *Target = nullptr;

                // Приоритет 1: Если функция сама содержит уязвимость, цель - уязвимый блок
                if (DirectlyVulnerableBlocksMap.count(F)) {
                    if (!DirectlyVulnerableBlocksMap[F].empty()) {
                        BasicBlock *VulnBB = *DirectlyVulnerableBlocksMap[F].begin();
                        if (!VulnBB->empty()) {
                            Target = &*VulnBB->begin();
                            errs() << "[PLAN-STACK] " << F->getName() << " is VULNERABLE. Target: Block " << VulnBB->getName() << "\n";
                        }
                    }
                }
                
                // Приоритет 2: Если уязвимости нет, ищем вызов следующей функции ИЗ СТЕКА
                if (!Target && calleesMap.count(F)) {
                    for (Function *Callee : calleesMap[F]) {
                        if (StackFunctions.count(Callee)) {
                            // Нашли вызов функции, которая тоже лежит на пути к уязвимости
                            // Ищем конкретную инструкцию вызова
                            for (BasicBlock &BB : *F) {
                                for (Instruction &I : BB) {
                                    if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                                        if (CI->getCalledFunction() == Callee) {
                                            Target = CI;
                                            errs() << "[PLAN-STACK] " << F->getName() << " calls next stack func: " << Callee->getName() << "\n";
                                            break;
                                        }
                                    }
                                }
                                if (Target) break;
                            }
                        }
                        if (Target) break;
                    }
                }

                if (Target) {
                    BasicBlock *TargetBlock = Target->getParent();
                    
                    // 1. Находим все блоки, которые лежат НА ПУТИ К цели (Backward)
                    std::set<BasicBlock*> BlocksBefore = getReachableBlocks(TargetBlock, false);
                    
                    // 2. Находим все блоки, которые лежат ПОСЛЕ цели (Forward)
                    std::set<BasicBlock*> BlocksAfter = getReachableBlocks(TargetBlock, true);
                    
                    // Объединяем их
                    std::set<BasicBlock*> ProtectedBlocks;
                    ProtectedBlocks.insert(BlocksBefore.begin(), BlocksBefore.end());
                    ProtectedBlocks.insert(BlocksAfter.begin(), BlocksAfter.end());

                    errs() << "[PLAN-STACK] " << F->getName() 
                           << ": Protected blocks: " << ProtectedBlocks.size() << "\n";

                    // 3. Ищем блоки для инструментации
                    for (BasicBlock &BB : *F) {
                        if (ProtectedBlocks.count(&BB)) {
                            continue;
                        }

                        // Блок не защищен. Это "боковая" ветка.
                        // Нам нужно понять, стоит ли её глушить.
                        // Глушим, если она ведет к выходу из функции (return) или exit.
                        
                        Instruction *Term = BB.getTerminator();
                        
                        // Вариант А: Блок сам содержит return
                        if (isa<ReturnInst>(Term)) {
                             plan.BlocksToWipeOut[F].insert(&BB);
                             printBlockTerminationTree(&BB, "Stack Func: Unprotected return block");
                             continue;
                        }

                        // Вариант Б: Блок содержит exit/abort
                        if (isTerminatingBlock(&BB, false)) {
                             plan.BlocksToWipeOut[F].insert(&BB);
                             printBlockTerminationTree(&BB, "Stack Func: Unprotected exit block");
                             continue;
                        }

                        // Вариант В: Блок делает br на unprotected return или просто на exit path?
                        // В нашем случае if.then делает br на return.
                        // Если return защищен (так как он после уязвимости), то br на него из незащищенного блока
                        // означает, что эта ветка прерывает путь к уязвимости.
                        
                        if (BranchInst *BI = dyn_cast<BranchInst>(Term)) {
                            // Если это безусловный переход или все пути ведут в тупик/выход
                            bool allSuccsAreExitOrProtectedReturn = true;
                            
                            // Эвристика: если блок имеет только одного successor, и этот successor - блок return,
                            // и текущий блок не ведет к уязвимости (мы это уже знаем, т.к. его нет в Protected),
                            // то это кандидат на глушение.
                            
                            // Но будьте осторожны: если br условный, нужно проверить обе ветки.
                            
                            // Для простоты: если блок не защищен, и он не ведет к уязвимости,
                            // мы можем вставить exit В НАЧАЛО этого блока.
                            // Это прервет выполнение здесь.
                            
                            // Давайте просто инструментировать ВСЕ незащищенные блоки, 
                            // которые являются "листьями" или ведут к return.
                            
                            // Проверим, ведет ли блок к return-блоку функции
                            bool leadsToReturn = false;
                            for (unsigned i = 0; i < BI->getNumSuccessors(); ++i) {
                                BasicBlock *Succ = BI->getSuccessor(i);
                                // Если successor - это блок с именем "return" или содержащий ret
                                if (Succ->getName().startswith("return") || isa<ReturnInst>(Succ->getTerminator())) {
                                    leadsToReturn = true;
                                }
                            }
                            
                            if (leadsToReturn) {
                                plan.BlocksToWipeOut[F].insert(&BB);
                                printBlockTerminationTree(&BB, "Stack Func: Unprotected branch leading to return");
                            }
                        }
                    }
                } else {
                    errs() << "[PLAN-STACK] " << F->getName() << " has no clear target. Preserving entirely.\n";
                }
            }

            // --- Обработка HELPER функций ---
            for (Function *F : HelperFunctions) {
                if (F->isDeclaration() || F->empty()) continue;
                
                // Для хелперов инструментируем ТОЛЬКО блоки с exit/abort
                for (BasicBlock &BB : *F) {
                    if (isTerminatingBlock(&BB, false)) { // false = ignore return
                        plan.BlocksToWipeOut[F].insert(&BB);
                        printBlockTerminationTree(&BB, "Helper Func: block contains exit/abort");
                    }
                }
            }

            // --- Обработка остальных функций (Wipe Out) ---
            for (Function &F : M) {
                if (F.isDeclaration() || F.empty()) continue;
                if (StackFunctions.count(&F) == 0 && HelperFunctions.count(&F) == 0) {
                    plan.FunctionsToWipeOut.insert(&F);
                    // errs() << "[PLAN-WIPE] Function outside cluster: " << F.getName() << "\n";
                }
            }

            errs() << "[SUMMARY] Stack Functions: " << StackFunctions.size() 
                   << ", Helper Functions: " << HelperFunctions.size() 
                   << ", Wiped Functions: " << plan.FunctionsToWipeOut.size() << "\n";

            return plan;
        }

		bool runOnModule(Module &M) override {
			loadConfig("vulnerabilities.cfg");
            findVulnerableFunctionsAndBlocks(M);
            
			if (DirectlyVulnerableBlocksMap.empty()) {
				errs() << "[PASS] No vulnerable functions found.\n";
				return false;
			}
			
            InstrumentationPlan plan = buildInstrumentationPlan(M);

            errs() << "\n--- EXECUTING PLAN ---\n";
			bool changed = false;
            
            // 1. Инструментируем функции целиком
            // for (Function *F : plan.FunctionsToWipeOut) {
            //     errs() << "[INSTRUMENT-FUNC] " << F->getName() << "\n";
            //     for (BasicBlock &BB : *F) {
            //         if (isa<UnreachableInst>(BB.getTerminator())) continue;
            //         Instruction *InsertPos = &*BB.getFirstNonPHI();
            //         if (InsertPos == BB.getTerminator()) InsertPos = BB.getTerminator();
            //         IRBuilder<> Builder(InsertPos);
            //         FunctionCallee ExitFn = M.getOrInsertFunction("exit", Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
            //         Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
            //         changed = true;
            //     }
            // }

            // 2. Инструментируем конкретные блоки
            for (auto &Entry : plan.BlocksToWipeOut) {
                Function *F = Entry.first;
                std::set<BasicBlock*> &Blocks = Entry.second;
                if (!Blocks.empty()) {
                    errs() << "[INSTRUMENT-BLOCKS] In " << F->getName() << " (" << Blocks.size() << " blocks)\n";
                }
                
                for (BasicBlock *BB : Blocks) {
                    if (isa<UnreachableInst>(BB->getTerminator())) continue;
                    Instruction *InsertPos = &*BB->getFirstNonPHI();
                    if (InsertPos == BB->getTerminator()) InsertPos = BB->getTerminator();
                    IRBuilder<> Builder(InsertPos);
                    FunctionCallee ExitFn = M.getOrInsertFunction("exit", Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
                    Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
                    changed = true;
                }
            }

            if (changed) errs() << "[PASS] Instrumentation complete.\n";
			return changed;
		}
	};
}

char VulnerablePathPass::ID = 0;
static RegisterPass<VulnerablePathPass> X("vuln-path", "Preserve only paths leading to vulnerabilities", false, false);