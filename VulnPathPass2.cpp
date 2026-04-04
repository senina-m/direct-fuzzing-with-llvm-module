#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <vector>
#include <queue>

using namespace llvm;

namespace {
  struct VulnerablePathPass : public ModulePass {
    static char ID;
    std::set<Function*> vulnerableFunctions;
    
    VulnerablePathPass() : ModulePass(ID) {}

    bool isVulnerable(Function &F) {
      errs() << "Checking function for vulnerabilities: " << F.getName() << "\n";
      
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto *CB = dyn_cast<CallBase>(&I)) {
            if (Function *Callee = CB->getCalledFunction()) {
              StringRef Name = Callee->getName();
              errs() << "  Found call to: " << Name << "\n";
              
              if (Name.contains("strcpy") || 
                  Name.contains("gets") ||
                  Name.contains("memcpy")) {
                errs() << "  !! VULNERABLE CALL DETECTED: " << Name << "\n";
                vulnerableFunctions.insert(Callee);
                return true;
              }
            }
          }
        }
      }
      return false;
    }

    void markVulnerableCallers(Module &M) {
      errs() << "\n=== Propagating vulnerability markers ===\n";
      unsigned iteration = 0;
      bool changed;
      
      do {
        changed = false;
        iteration++;
        errs() << "Iteration " << iteration << ":\n";
        
        for (Function &F : M) {
          if (vulnerableFunctions.count(&F)) {
            errs() << "  " << F.getName() << ": already marked\n";
            continue;
          }
          
          errs() << "  Checking " << F.getName() << " callers:\n";
          for (auto &BB : F) {
            for (auto &I : BB) {
              if (auto *CB = dyn_cast<CallBase>(&I)) {
                if (Function *Callee = CB->getCalledFunction()) {
                  if (vulnerableFunctions.count(Callee)) {
                    errs() << "    Calls vulnerable function: " << Callee->getName() << "\n";
                    vulnerableFunctions.insert(&F);
                    changed = true;
                    errs() << "    !! MARKED AS VULNERABLE: " << F.getName() << "\n";
                    goto next_function; // Skip remaining instructions
                  }
                }
              }
            }
          }
          next_function:;
        }
      } while (changed);
      
      errs() << "Completed in " << iteration << " iterations\n";
    }

    void transformSafeCalls(Module &M) {
      errs() << "\n=== Transforming safe calls ===\n";
      unsigned transforms = 0;
      errs() << "Total: " << vulnerableFunctions.size() << " vulnerable functions\n";
      
      for (Function &F : M) {
        if (F.isDeclaration()) continue;
        
        errs() << "Processing function: " << F.getName() << "\n";
        for (auto &BB : F) {
          for (auto &I : BB) {
            if (auto *CB = dyn_cast<CallBase>(&I)) {
              if (Function *Callee = CB->getCalledFunction()) {
                errs() << "  Found call to: " << Callee->getName();
                
                if (!vulnerableFunctions.count(Callee)) {
                  errs() << " (SAFE - inserting exit)\n";
                  
                  // Insert exit before call
                  IRBuilder<> Builder(CB);
                  FunctionType *ExitTy = FunctionType::get(
                      Type::getVoidTy(M.getContext()),
                      {Type::getInt32Ty(M.getContext())}, 
                      false);
                  FunctionCallee ExitFn = M.getOrInsertFunction("exit", ExitTy);
                  Builder.CreateCall(ExitFn, {Builder.getInt32(0)});
                  transforms++;
                  
                  errs() << "  ++ Inserted exit() before call to " << Callee->getName() << "\n";
                } else {
                  errs() << " (VULNERABLE - preserving)\n";
                }
              }
            }
          }
        }
      }
      errs() << "Total safe calls transformed: " << transforms << "\n";
    }

    bool runOnModule(Module &M) override {
      errs() << "\n======= Starting Vulnerability Analysis =======\n";
      
      // Phase 1: Direct vulnerability detection
      errs() << "\n=== Phase 1: Direct Vulnerability Detection ===\n";
      for (Function &F : M) {
        if (isVulnerable(F)) {
          errs() << "Marked as vulnerable: " << F.getName() << "\n";
          vulnerableFunctions.insert(&F);
        }
      }
      
      // Phase 2: Call graph propagation
      markVulnerableCallers(M);
      
      // Phase 3: Transformation
      transformSafeCalls(M);
      
      // Summary
      errs() << "\n======= Analysis Complete =======\n";
      errs() << "Total vulnerable functions: " << vulnerableFunctions.size() << "\n";
      errs() << "List of vulnerable functions:\n";
      for (Function *F : vulnerableFunctions) {
        errs() << "  " << F->getName() << "\n";
      }
      
      return true;
    }
  };
}

char VulnerablePathPass::ID = 0;

static RegisterPass<VulnerablePathPass> X(
    "vuln-path", 
    "Isolate Vulnerable Paths Pass",
    false,
    false
);