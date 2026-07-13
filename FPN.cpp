#include "config.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/TargetFolder.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/OptimizationLevel.h" 
#include <algorithm>
#include <iostream>
using namespace llvm;
using namespace std;
#define DEBUG_TYPE ""
#define REPORT
/* Runtime Function List */

#define __REPORT_STATISTIC "ReportStatistic"
#define __ESCAPE "RegPtr"

#define STRING(a) STRING2(a)
#define STRING2(a) #a
#define REPLACE2(M, N, alloc) \
  do { \
  if (Function *F0 = (M)->getFunction(N)) { \
  FunctionCallee F1 = (M)->getOrInsertFunction("fastPN_" N, \
  F0->getFunctionType()); \
  F0->replaceAllUsesWith(F1.getCallee()); \
  Function *F2 = dyn_cast<Function>(F1.getCallee()); \
  if ((alloc == 1) && F2 != nullptr) { \
  F2->setDoesNotThrow(); \
  F2->setReturnDoesNotAlias(); \
  } \
  } \
  } while (false);
#define REPLACE(M, F, alloc) REPLACE2(M, STRING(F), alloc)


namespace {
//replacing the original malloc fucntions by FPN version malloc functions
void replaceLibFuncs(Module *M){

 REPLACE(M, malloc, 1); 
 REPLACE(M, calloc, 1);
 REPLACE(M, realloc, 1); 

 REPLACE(M, aligned_alloc, 1);
 REPLACE(M, valloc, 1);
 REPLACE(M, memalign, 1);
 REPLACE(M, pvalloc, 1);
 //REPLACE(M, strdup, 1);
 //REPLACE(M, mem2chunk, 3);
 //REPLACE(M, strndup, 1);
 
 REPLACE2(M, "_Znwm", 1); 
 REPLACE2(M, "_Znam", 1); 
 REPLACE2(M, "_ZnwmRKSt9nothrow_t", 1); 
 REPLACE2(M, "_ZnamRKSt9nothrow_t", 1); 
 
 REPLACE(M, free, 2);
 
 REPLACE2(M, "_ZdlPv", 2); 
 REPLACE2(M, "_ZdaPv", 2); 
 
}

struct FPNPass : public PassInfoMixin<FPNPass> {

  // Basic
  Module *M;
  Function *F;
  const DataLayout *DL;

  // Type Utils
  Type *voidType;
  Type *int32Type;
  Type *int64Type;
  Type *voidPointerType;
  Type *int64PointerType;

  // Statistic
  int64_t escapeTrace;
  int64_t escapeOptimized;

  // Instruction
  DenseMap<Value *, Value *> source;
  DenseMap<Value *, SmallVector<Instruction *, 16> *> cluster;

  SmallSet<Instruction *, 16> escaped;
  SmallSet<Instruction *, 16> auxiliary;
  SmallVector<Instruction *, 16> runtimeCheck;
  SmallVector<std::pair<Instruction *, Value *>, 16> builtinCheck;
  SmallVector<std::pair<Value *, SmallVector<Instruction *, 16> *>, 16>
  partialCheck;

  SmallVector<StoreInst *, 16> storeInsts;

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
    if (!F.isIntrinsic() && !isInternalFunction(F.getName()) && F.getInstructionCount() > 0) {

      this->F = &F;
      M = F.getParent();
      DL = &M->getDataLayout();
      
      escapeTrace = 0;
      escapeOptimized = 0;

      source.clear();
      cluster.clear();
      escaped.clear();
      auxiliary.clear();
      runtimeCheck.clear();
      builtinCheck.clear();
      partialCheck.clear();
      storeInsts.clear();

      bindRuntime();
      replaceLibFuncs(M);
      hookInstruction();

      if (F.getName() == "main")
        insertReport();
      report();
      return PreservedAnalyses::none();
    }
  return PreservedAnalyses::all();;
  }

  static bool isInternalFunction(StringRef name) {
    static StringSet<> ifunc = {
      __REPORT_STATISTIC, __ESCAPE,
    };
    return ifunc.count(name) != 0;
  }

  void bindRuntime() {
    LLVMContext &context = M->getContext();
    voidType = Type::getVoidTy(context);
    int32Type = Type::getInt32Ty(context);
    int64Type = Type::getInt64Ty(context);
    llvm::Type* i8Type = llvm::Type::getInt8Ty(context); 
    
    llvm::PointerType* voidPointerType = llvm::PointerType::get(context, 0); // Get a pointer to the 8-bit integer type
    llvm::Type* int64Type = llvm::Type::getInt64Ty(context); // Get the i64 type
    llvm::Type* int64PointerType = llvm::PointerType::get(int64Type, 0); // Get a pointer to i64 in address space 0

    M->getOrInsertFunction(__REPORT_STATISTIC, FunctionType::get(voidType, {}, false));
    M->getOrInsertFunction(__ESCAPE, FunctionType::get(int32Type, {voidPointerType, voidPointerType}, false));

  }

  //insert report functions such as breakdown analysis of each component, number of reduced registeration operations, etc.
  void insertReport() {
    SmallVector<Instruction *, 16> returns;
    SmallVector<Instruction *, 16> calls;
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB) {
        if (ReturnInst *ret = dyn_cast<ReturnInst>(&I))
          returns.push_back(ret);
        if (CallInst *call = dyn_cast<CallInst>(&I))
          calls.push_back(call);
      }

    for (auto ret : returns) {
      IRBuilder<> irBuilder(ret);
      #ifdef REPORT
      irBuilder.CreateCall(M->getFunction(__REPORT_STATISTIC));
      #endif
    }

    // Avoid directly call exit(status) in main() function, instead of return,
    // such as 600.perlbench_s
    for (auto I : calls) {
      CallInst *call = dyn_cast<CallInst>(I);
      Function *fp = call->getCalledFunction();

      if (fp != nullptr && fp->getName() == "exit") {
        IRBuilder<> irBuilder(call);
        #ifdef REPORT
        irBuilder.CreateCall(M->getFunction(__REPORT_STATISTIC));
        #endif
      }
    }
  }

  void report() {
    dbgs() << "[REPORT:" << F->getName() << "]\n";
    if (escapeTrace > 0) {
      dbgs() << " [Escape]\n";
      dbgs() << " Escape Optimized: " << escapeOptimized << " \n";
      dbgs() << " Escape Trace: " << escapeTrace << " \n";
    }
  }

  void hookInstruction() {
    collectInformation();
    escapeOptimize();
    applyInstrument();
  }


  Value *readRegister(IRBuilder<> &IRB, StringRef Name) {
    Function *readReg = Intrinsic::getDeclaration(M, Intrinsic::read_register,
    IRB.getIntPtrTy(*DL));

    LLVMContext &context = M->getContext();
    MDNode *MD = MDNode::get(context, {MDString::get(context, Name)});
    return IRB.CreateCall(readReg, {MetadataAsValue::get(context, MD)});
  }

  void addEscape(StoreInst *SI) {
    IRBuilder<> IRB(SI);

    // x86-64 only
    // heap address < stack address

    Value *rsp = readRegister(IRB, "rsp");
    Value *value = IRB.CreatePtrToInt(SI->getValueOperand(), int64Type);
    Value *valueNotOnStack = IRB.CreateICmpULT(value, rsp);
    Value *valueIsNotNull =
    IRB.CreateICmpNE(value, Constant::getNullValue(int64Type));
    Value *cond = IRB.CreateAnd(valueNotOnStack, valueIsNotNull);
    IRB.SetInsertPoint(SplitBlockAndInsertIfThen(cond, SI, false));
    IRB.CreateCall(M->getFunction(__ESCAPE), {SI->getPointerOperand(), SI->getValueOperand()});
  }

  bool allocateChecker(
    Instruction *Ptr, SmallVector<Instruction *, 16> &runtimeCheck,
    SmallVector<std::pair<Instruction *, Value *>, 16> &builtinCheck) {
    assert(Ptr->getType()->isPointerTy() &&
    "allocateChecker(): Ptr should be pointer type");

    return true;
  }

  bool searchPhi(Value *V, Value *&src, SmallSet<Value *, 16> &Visit) {
    if (Visit.count(V))
      return true;
    Visit.insert(V);
    if (PHINode *phi = dyn_cast<PHINode>(V)) {
      for (int i = 0; i < phi->getNumIncomingValues(); ++i) {
        if (!searchPhi(phi->getIncomingValue(i), src, Visit))
          return false;
      }
      return true;
    }
    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V)) {
      return searchPhi(gep->getPointerOperand(), src, Visit);
    }
    if (BitCastInst *bc = dyn_cast<BitCastInst>(V)) {
      return searchPhi(bc->getOperand(0), src, Visit);
    }
    if (GEPOperator *gepo = dyn_cast<GEPOperator>(V)) {
      return searchPhi(gepo->getPointerOperand(), src, Visit);
    }
    if (src == nullptr) {
      src = V;
      return true;
    }
    return src == V;
  }

  Value *findSource(Value *V) {
    if (Instruction *I = dyn_cast<Instruction>(V)) {
      if (source.count(I)) {
        return source[I];
      }
    }
    if (PHINode *phi = dyn_cast<PHINode>(V)) {
      Value *src = nullptr;
      SmallSet<Value *, 16> Visit;
      if (searchPhi(phi, src, Visit))
        return source[phi] = src;
      else
        return source[phi] = phi;
    }
    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V)) {
      return source[gep] = findSource(gep->getPointerOperand());
    }
    if (BitCastInst *bc = dyn_cast<BitCastInst>(V)) {
      return source[bc] = findSource(bc->getOperand(0));
    }
    if (GEPOperator *gepo = dyn_cast<GEPOperator>(V)) {
      return findSource(gepo->getPointerOperand());
    }
    return V;
  }

  void collectInformation() {
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB) {
        if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
          if (SI->getValueOperand()->getType()->isPointerTy()) {
            if (isa<AllocaInst>(SI->getValueOperand()) || isa<ConstantPointerNull>(SI->getValueOperand())) {
              escapeOptimized++;
              continue;
            }
            Instruction *ptr = dyn_cast_or_null<Instruction>(SI->getValueOperand());
            if (ptr && source.count(ptr) && isa<AllocaInst>(source[ptr])) {
              escapeOptimized++;
              continue;
            }
            storeInsts.push_back(SI);
          }
        }
    }
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB)
        findSource(&I);
  }



  bool isMustEscapeInstruction(User *I) {
    if (isa<StoreInst>(I) || isa<ReturnInst>(I))
      return true;

    if (auto CB = dyn_cast<CallBase>(I)) {
      Function *F = CB->getCalledFunction();
      if (F != nullptr) {
        static SmallVector<StringRef, 16> whitelist = {
          "llvm.prefetch.",
          "llvm.lifetime.start",
          "llvm.lifetime.end",
        };
        for (auto name : whitelist) {
          if (F->getName().startswith(name))
            return false;
        }
      }
      return true;
    }

    return false;
  }

  void escapeOptimize() {
    SmallVector<StoreInst *, 16> newStoreInsts;
    for (auto *SI : storeInsts) {
      bool flag = false;
      if (auto I = dyn_cast<Instruction>(SI->getValueOperand()))
        if (source.count(I))
          if (LoadInst *LI = dyn_cast<LoadInst>(source[I]))
            if (LI->getPointerOperand() == SI->getPointerOperand())
              flag = true;
      if (flag)
        escapeOptimized++;
      else
        newStoreInsts.push_back(SI);
    }
    storeInsts.swap(newStoreInsts);
  }

  void applyInstrument() {
    for (auto SI : storeInsts) {
      escapeTrace++;
      addEscape(SI);
    }
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "FPNPass", "0.1",
    [](PassBuilder &PB) {
      // Allow `-passes="function(my-func-pass)"`
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM,
           ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "FPN-pass") {
            FPM.addPass(FPNPass());
            return true;
          }
          return false;
        });

        PB.registerOptimizerLastEPCallback([&](ModulePassManager &MPM, llvm::OptimizationLevel Level) {
            FunctionPassManager FPM;
            FPM.addPass(FPNPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        });

    }
};
}
