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

    enum class FuncRole {
        STACK_FUNC,   // Лежит на пути к уязвимости, имеет критический вызов дальше
        HELPER_FUNC,  // Вызывается на пути, но сама не ведет дальше к уязвимости (или leaf)
        UNKNOWN       // Не в кластере
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
                                }
                            }
                        }
                    }
                }
            }
        }

        void preserveFunctionsByName(Module &M, std::set<Function*> &cluster, const std::string &nameSubstring) {
            for (Function &F : M) {
                if (F.isDeclaration()) continue;
                if (F.getName().contains(nameSubstring)) {
                    cluster.insert(&F);
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

        InstrumentationPlan buildInstrumentationPlan(Module &M) {
            InstrumentationPlan plan;
            std::set<Function*> preservedCluster; 
            
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

            // 2. Инициализируем кластер от уязвимых функций
            std::queue<Function*> q;
            for (auto &Pair : DirectlyVulnerableBlocksMap) {
                if (preservedCluster.insert(Pair.first).second) q.push(Pair.first);
            }
            
            // Добавляем принудительно сохраненные по имени
            preserveFunctionsByName(M, preservedCluster, "xmlMemRead");

            // BFS для полного кластера
            while (!q.empty()) {
                Function *Curr = q.front(); q.pop();
                // Backward
                if (callersMap.count(Curr)) {
                    for (Function *Caller : callersMap[Curr]) {
                        if (preservedCluster.insert(Caller).second) q.push(Caller);
                    }
                }
                // Forward
                if (calleesMap.count(Curr)) {
                    for (Function *Callee : calleesMap[Curr]) {
                        if (preservedCluster.insert(Callee).second) q.push(Callee);
                    }
                }
            }

            // 3. Определяем роли функций и Critical Calls
            // Stack Function: та, у которой есть вызов функции из кластера, которая "ближе" к уязвимости.
            // Для простоты: если F вызывает G, и G в кластере, то вызов G в F - критический.
            
            std::map<Function*, Instruction*> CriticalCallMap; // Func -> CallInst leading deeper
            
            // Чтобы определить "глубину", можно использовать расстояние от уязвимости.
            // Но для начала просто пометим: если функция вызывает кого-то из кластера, она Stack.
            // Исключение: если она сама уязвима, она тоже Stack (цель - сам уязвимый блок).
            
            std::set<Function*> StackFunctions;
            std::set<Function*> HelperFunctions;

            for (Function *F : preservedCluster) {
                bool isStack = false;
                
                // Проверка: вызывает ли она кого-то из кластера?
                if (calleesMap.count(F)) {
                    for (Function *Callee : calleesMap[F]) {
                        if (preservedCluster.count(Callee)) {
                            // Нашли первый попавшийся вызов в кластер. 
                            // В идеале нужно выбирать тот, что ведет к уязвимости, но в связном графе кластера
                            // любой вызов внутрь кластера (кроме циклов) обычно ведет к цели.
                            // Возьмем первый найденный CallInst для этого Callee.
                            for (BasicBlock &BB : *F) {
                                for (Instruction &I : BB) {
                                    if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                                        if (CI->getCalledFunction() == Callee) {
                                            CriticalCallMap[F] = CI;
                                            isStack = true;
                                            break;
                                        }
                                    }
                                }
                                if (isStack) break;
                            }
                        }
                        if (isStack) break;
                    }
                }

                // Если функция сама содержит уязвимость, она тоже Stack (цель - уязвимый блок)
                if (DirectlyVulnerableBlocksMap.count(F)) {
                    isStack = true;
                    // Для уязвимой функции целью является первая инструкция уязвимого блока
                    if (!DirectlyVulnerableBlocksMap[F].empty()) {
                        BasicBlock *VulnBB = *DirectlyVulnerableBlocksMap[F].begin();
                        if (!VulnBB->empty()) {
                            CriticalCallMap[F] = &*VulnBB->begin();
                        }
                    }
                }

                if (isStack) {
                    StackFunctions.insert(F);
                    errs() << "[" << F->getName() << "] " <<  "Stask function" << "\n";
                } else {
                    HelperFunctions.insert(F);
                    errs() << "[" << F->getName() << "] " << "Helper function" << "\n";
                }
            }

            // 4. Формируем план инструментации блоков
            for (Function *F : preservedCluster) {
                if (F->isDeclaration() || F->empty()) continue;

                if (StackFunctions.count(F)) {
                    // --- ЛОГИКА ДЛЯ STACK FUNCTION ---
                    // Ищем блоки, не ведущие к Critical Call
                    Instruction *Target = CriticalCallMap[F];
                    if (Target) {
                        std::set<Instruction*> Targets = {Target};
                        std::set<BasicBlock*> NonLeadingBlocks = findBlocksNotLeadingToTargets(F, Targets);
                        
                        for (BasicBlock *BB : NonLeadingBlocks) {
                            // errs() << "[&&&&&] " << BB->getName() << "' NonLeadingBlocks " << "\n";
                            // Инструментируем только если блок завершается return или exit
                            // if (isTerminatingBlock(BB, true)) { // true = check return
                                plan.BlocksToWipeOut[F].insert(BB);
                                printBlockTerminationTree(BB, "Stack Func: block does not lead to critical call and has return/exit");
                            // }
                        }
                    }
                } else if (HelperFunctions.count(F)) {
                    // --- ЛОГИКА ДЛЯ HELPER FUNCTION ---
                    // Инструментируем только блоки с exit/abort
                    for (BasicBlock &BB : *F) {
                        if (isTerminatingBlock(&BB, false)) { // false = ignore return, check only exit/abort
                            plan.BlocksToWipeOut[F].insert(&BB);
                            printBlockTerminationTree(&BB, "Helper Func: block contains exit/abort");
                        }
                    }
                }
            }

            // Функции вне кластера глушим целиком
            for (Function &F : M) {
                if (F.isDeclaration() || F.empty()) continue;
                if (preservedCluster.count(&F) == 0) {
                    plan.FunctionsToWipeOut.insert(&F);
                }
            }

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
            
            // 1. Глушим функции целиком
            for (Function *F : plan.FunctionsToWipeOut) {
                errs() << "[INSTRUMENT-FUNC] " << F->getName() << "\n";
                for (BasicBlock &BB : *F) {
                    if (isa<UnreachableInst>(BB.getTerminator())) continue;
                    Instruction *InsertPos = &*BB.getFirstNonPHI();
                    if (InsertPos == BB.getTerminator()) InsertPos = BB.getTerminator();
                    IRBuilder<> Builder(InsertPos);
                    FunctionCallee ExitFn = M.getOrInsertFunction("exit", Type::getVoidTy(M.getContext()), Type::getInt32Ty(M.getContext()));
                    Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
                    changed = true;
                }
            }

            // 2. Глушим конкретные блоки
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
