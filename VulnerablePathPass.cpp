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

namespace {
  struct VulnerabilityLocation {
    std::string function;
    unsigned line;
  };
  
  void dumpVulnerableBlocks(const std::set<BasicBlock*> &blocks, const Function &F) {
    errs() << "Vulnerable blocks in function " << F.getName() << ":\n";
    if (blocks.empty()) {
      errs() << "  [none]\n";
      return;
    }
    for (BasicBlock *BB : blocks) {
      errs() << "  ";
      BB->printAsOperand(errs(), false); // печатает имя, например %if.then
      errs() << "\n";
    }
  }

  void dumpVulnerableFunctions(const std::set<Function*> &vulnFuncs) {
    errs() << "Vulnerable functions:\n";
    if (vulnFuncs.empty()) {
      errs() << "  [none]\n";
      return;
    }
    for (Function *F : vulnFuncs) {
      errs() << "  " << F->getName() << "\n";
    }
  }

  struct VulnerablePathPass : public ModulePass {
    static char ID;
    std::unordered_map<std::string, std::vector<std::pair<std::string, unsigned>>> ConfigVulns;

    VulnerablePathPass() : ModulePass(ID) {}

    void loadConfig(const std::string &configPath) {
      std::ifstream file(configPath);
      if (!file.is_open()) return;

      std::string line;
      std::string currentFile;
      while (std::getline(file, line)) {
        // Пропускаем пустые строки и комментарии
        if (line.empty() || line[0] == '#') continue;

        if (line.rfind("[file: ", 0) == 0) {
          size_t end = line.find(']');
          if (end != std::string::npos) {
            currentFile = line.substr(7, end - 7);
          }
        } else if (line.rfind("function: ", 0) == 0) {
          std::string func = line.substr(10);
          std::getline(file, line); // следующая строка — line
          if (line.rfind("line: ", 0) == 0) {
            unsigned ln = std::stoul(line.substr(6));
            ConfigVulns[currentFile].emplace_back(func, ln);
          }
        }
      }
    }

    // Проверяет, содержит ли инструкция ПРЯМУЮ уязвимость
    bool isDirectlyVulnerable(Instruction &I) {
      // Получаем отладочную информацию
      const DebugLoc &DL = I.getDebugLoc();
      if (!DL) return false;

      // Получаем номер строки
      unsigned line = DL.getLine();
      if (line == 0) return false;

      // Получаем функцию, в которой находится инструкция
      Function *F = I.getFunction();
      if (!F) return false;
      StringRef funcName = F->getName();

      // Получаем имя исходного файла
      DILocation *Loc = DL.get();
      if (!Loc) return false;
      std::string fileName = Loc->getFilename().str();

      // Убираем путь, оставляем только имя файла (если нужно)
      // Например: "/home/user/test.c" → "test.c"
      size_t lastSlash = fileName.find_last_of("/\\");
      if (lastSlash != std::string::npos) {
        fileName = fileName.substr(lastSlash + 1);
      }

      // Проверяем конфигурацию
      auto it = ConfigVulns.find(fileName);
      if (it == ConfigVulns.end()) return false;

      for (const auto &entry : it->second) {
        const std::string &cfgFunc = entry.first;
        unsigned cfgLine = entry.second;
        if (funcName == cfgFunc && line == cfgLine) {
          return true;
        }
      }
      return false;
    }

    // Собирает уязвимые функции, ИСКЛЮЧАЯ main
    std::set<Function*> collectVulnerableFunctions(Module &M) {
      std::set<Function*> vulnFuncs;
      for (Function &F : M) {
        if (F.isDeclaration()) continue;
        if (F.getName() == "main") continue; // ← КЛЮЧЕВОЕ: main не может быть "уязвимой функцией"
        for (BasicBlock &BB : F) {
          for (Instruction &I : BB) {
            if (isDirectlyVulnerable(I)) {
              vulnFuncs.insert(&F);
              break;
            }
          }
        }
      }
      return vulnFuncs;
    }

    // Для main: найти блоки, которые ВЫЗЫВАЮТ уязвимые функции
    std::set<BasicBlock*> findVulnerablePathsInMain(Function &Main, const std::set<Function*> &vulnFuncs) {
      std::set<BasicBlock*> vulnerableBlocks;
      std::queue<BasicBlock*> worklist;

      // Шаг 1: найти блоки с вызовами уязвимых функций
      for (BasicBlock &BB : Main) {
        bool callsVuln = false;
        for (Instruction &I : BB) {
          if (CallInst *CI = dyn_cast<CallInst>(&I)) {
            if (Function *F = CI->getCalledFunction()) {
              if (vulnFuncs.count(F)) {
                callsVuln = true;
                break;
              }
            }
          }
        }
        if (callsVuln) {
          vulnerableBlocks.insert(&BB);
          worklist.push(&BB);
        }
      }

      // Шаг 2: ОБРАТНЫЙ обход — всё, что ведёт К вызову
      std::queue<BasicBlock*> backwardWork = worklist; // копия
      while (!backwardWork.empty()) {
        BasicBlock *BB = backwardWork.front();
        backwardWork.pop();
        for (BasicBlock *Pred : predecessors(BB)) {
          if (vulnerableBlocks.insert(Pred).second) {
            backwardWork.push(Pred);
          }
        }
      }

      // Шаг 3: ПРЯМОЙ обход — всё, что выполняется ПОСЛЕ вызова
      std::queue<BasicBlock*> forwardWork;
      for (BasicBlock *BB : vulnerableBlocks) {
        forwardWork.push(BB);
      }
      while (!forwardWork.empty()) {
        BasicBlock *BB = forwardWork.front();
        forwardWork.pop();
        for (BasicBlock *Succ : successors(BB)) {
          if (vulnerableBlocks.insert(Succ).second) {
            forwardWork.push(Succ);
          }
        }
      }

      return vulnerableBlocks;
    }
    // Для обычных функций: найти блоки с прямыми уязвимостями
    std::set<BasicBlock*> findVulnerablePathsInFunction(Function &F) {
      std::set<BasicBlock*> vulnerableBlocks;
      std::queue<BasicBlock*> worklist;

      for (BasicBlock &BB : F) {
        bool hasVuln = false;
        for (Instruction &I : BB) {
          if (isDirectlyVulnerable(I)) {
            hasVuln = true;
            break;
          }
        }
        if (hasVuln) {
          vulnerableBlocks.insert(&BB);
          worklist.push(&BB);
        }
      }

      // Обратный обход
      while (!worklist.empty()) {
        BasicBlock *BB = worklist.front();
        worklist.pop();
        for (BasicBlock *Pred : predecessors(BB)) {
          if (vulnerableBlocks.insert(Pred).second) {
            worklist.push(Pred);
          }
        }
      }

      return vulnerableBlocks;
    }

    void dumpVulnerableBlocks(const std::set<BasicBlock*> &blocks, const Function &F) {
      errs() << "Vulnerable blocks in " << F.getName() << ":\n";
      for (BasicBlock *BB : blocks) {
        errs() << "  ";
        BB->printAsOperand(errs(), false);
        errs() << "\n";
      }
    }

    bool runOnModule(Module &M) override {
      loadConfig("vulnerabilities.cfg");
      std::set<Function*> vulnFuncs = collectVulnerableFunctions(M);
      if (vulnFuncs.empty()) {
        errs() << "No vulnerable functions found (excluding main)\n";
        return false;
      }

      errs() << "Found " << vulnFuncs.size() << " vulnerable function(s)\n";

      bool changed = false;

      for (Function &F : M) {
        if (F.isDeclaration()) continue;

        std::set<BasicBlock*> vulnerableBlocks;
        if (F.getName() == "main") {
          vulnerableBlocks = findVulnerablePathsInMain(F, vulnFuncs);
        } else {
          vulnerableBlocks = findVulnerablePathsInFunction(F);
        }

        dumpVulnerableBlocks(vulnerableBlocks, F);

        // 🔥 ЗАМЕНА ВСЕГО БЛОКА НА exit(0)
        for (BasicBlock &BB : F) {
          if (vulnerableBlocks.count(&BB)) {
            continue;
          }

          // Удаляем всё содержимое блока
          BB.getInstList().clear();

          // Вставляем exit(0); unreachable
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
    "Preserve only paths leading to vulnerabilities",
    false,
    false
);