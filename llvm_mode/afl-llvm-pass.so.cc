/*
  afl-llvm-pass.so.cc - LLVM instrumentation pass
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <set>
#include <string>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
// #include "llvm/IR/AllocaInst.h" // Removed to avoid file not found on old LLVM

using namespace llvm;

namespace {

  static std::set<std::string> AutoDictStringTokens;
  static std::set<std::string> AutoDictIntTokens;
  static std::set<std::string> AutoDictDumpedStrings;
  static std::set<std::string> AutoDictDumpedInts;

  static std::string escapeForAFLDict(const std::string &in) {
    std::string out;
    out.reserve(in.size() + 2);
    out.push_back('"');
    for (unsigned char c : in) {
      if (c == '\\' || c == '"') {
        out.push_back('\\');
        out.push_back(c);
      } else if (c >= 0x20 && c <= 0x7e && c != '\n' && c != '\r' && c != '\t') {
        out.push_back(c);
      } else {
        char buf[5];
        snprintf(buf, sizeof(buf), "\\x%02x", c);
        out.append(buf);
      }
    }
    out.push_back('"');
    return out;
  }

  static bool isLikelyKeyword(const std::string &s) {
    if (s.size() < 3 || s.size() > 64) return false;
    bool has_alpha = false;
    for (unsigned char c : s) {
      if (c < 0x20 || c > 0x7e) return false;
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') return false;
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) has_alpha = true;
    }
    return has_alpha;
  }

  static bool isLikelyMagicInt(uint64_t v, unsigned bitWidth) {
    if (bitWidth != 16 && bitWidth != 32) return false;
    if (v == 0 || v == 1) return false;
    if (v <= 0xff) return false;
    uint64_t maxVal = (bitWidth == 16) ? 0xffffu : 0xffffffffu;
    if (v == maxVal) return false;
    if ((v & (v - 1)) == 0) return false;
    return true;
  }

  static void addMagicIntTokens(uint64_t v, unsigned bitWidth) {
    if (!isLikelyMagicInt(v, bitWidth)) return;
    unsigned bytes = bitWidth / 8;
    if (bytes != 2 && bytes != 4) return;
    unsigned char buf_le[4] = {0};
    for (unsigned i = 0; i < bytes; ++i) buf_le[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    std::string token_le;
    token_le.reserve(4 * bytes + 2);
    token_le.push_back('"');
    for (unsigned i = 0; i < bytes; ++i) {
      char tmp[5];
      snprintf(tmp, sizeof(tmp), "\\x%02x", buf_le[i]);
      token_le.append(tmp);
    }
    token_le.push_back('"');
    AutoDictIntTokens.insert(token_le);

    unsigned char buf_be[4] = {0};
    for (unsigned i = 0; i < bytes; ++i) buf_be[bytes - 1 - i] = buf_le[i];
    std::string token_be;
    token_be.reserve(4 * bytes + 2);
    token_be.push_back('"');
    for (unsigned i = 0; i < bytes; ++i) {
      char tmp[5];
      snprintf(tmp, sizeof(tmp), "\\x%02x", buf_be[i]);
      token_be.append(tmp);
    }
    token_be.push_back('"');
    AutoDictIntTokens.insert(token_be);
  }

  static void dumpAutoDictIfRequested() {
    char *dict_path = getenv("AFL_AUTO_DICT");
    if (!dict_path || !dict_path[0]) return;
    FILE *f = fopen(dict_path, "a");
    if (!f) return;
    for (const auto &tok : AutoDictStringTokens) {
      if (AutoDictDumpedStrings.insert(tok).second) {
        fprintf(f, "%s\n", tok.c_str());
      }
    }
    for (const auto &tok : AutoDictIntTokens) {
      if (AutoDictDumpedInts.insert(tok).second) {
        fprintf(f, "%s\n", tok.c_str());
      }
    }
    fclose(f);
  }

  class AFLCoverage : public ModulePass {
    public:
      static char ID;
      AFLCoverage() : ModulePass(ID) { }
      bool runOnModule(Module &M) override;
  };

}

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  char *auto_dict_env = getenv("AFL_AUTO_DICT");
  bool  auto_dict_enabled = auto_dict_env && auto_dict_env[0];

  char *taint_env = getenv("AFL_TAINT_ANALYSIS");
  bool  taint_enabled = taint_env && taint_env[0];
  
  static unsigned int cmp_id_counter = 1;

  char be_quiet = 0;
  if (isatty(2) && !getenv("AFL_QUIET")) {
    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");
  } else be_quiet = 1;

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio || inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  int inst_blocks = 0;

  if (auto_dict_enabled) {
    for (auto &G : M.globals()) {
      if (!G.hasInitializer()) continue;
      Constant *Init = G.getInitializer();
      auto *CDA = dyn_cast<ConstantDataArray>(Init);
      if (!CDA || !CDA->isString()) continue;
      std::string s = CDA->getAsCString().str();
      if (!isLikelyKeyword(s)) continue;
      AutoDictStringTokens.insert(escapeForAFLDict(s));
    }
  }

  for (auto &F : M)
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      unsigned int cur_loc = AFL_R(MAP_SIZE);
      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr,
                        IRB.CreateAdd(IRB.CreateURem(IRB.CreateXor(PrevLocCasted, CurLoc), ConstantInt::get(Int32Ty, MAP_SIZE - SHIFT_SIZE)), ConstantInt::get(Int32Ty, SHIFT_SIZE)));

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      if (auto_dict_enabled) {
        for (auto &I : BB) {
          for (unsigned oi = 0; oi < I.getNumOperands(); ++oi) {
            Value *Op = I.getOperand(oi);
            auto *CI = dyn_cast<ConstantInt>(Op);
            if (!CI) continue;
            unsigned bw = CI->getBitWidth();
            if (bw != 16 && bw != 32) continue;
            uint64_t v = CI->getZExtValue();
            addMagicIntTokens(v, bw);
          }
        }
      }

      if (taint_enabled) {

        for (auto &I : BB) {

          if (auto *ICmp = dyn_cast<ICmpInst>(&I)) {
            
            bool is_candidate = false;
            for (auto it = I.getIterator(); it != BB.end(); ++it) {
              if (auto *Br = dyn_cast<BranchInst>(&*it)) {
                if (Br->isConditional()) {
                  is_candidate = true;
                  break;
                }
              }
            }
            
            if (!is_candidate) continue;
            
            unsigned int cmp_id = cmp_id_counter++;
            if (cmp_id >= 4096) continue;
            
            Value *Op1 = ICmp->getOperand(0);
            Value *Op2 = ICmp->getOperand(1);
            
            FunctionType *CheckTaintTy = FunctionType::get(
                Type::getVoidTy(C),
                {Int32Ty, PointerType::get(Int8Ty, 0), PointerType::get(Int8Ty, 0)},
                false);
            
            Constant *CheckTaintFn = M.getOrInsertFunction("__afl_check_taint", CheckTaintTy);
            
            IRBuilder<> TaintIRB(&I);
            TaintIRB.SetInsertPoint(&I);
            TaintIRB.SetInsertPoint(I.getNextNode());
            
            /* [修改] 使用 Int32Ty 作为返回值 */
            FunctionType *GetTaintTy = FunctionType::get(
                Int32Ty,  
                {PointerType::get(Int8Ty, 0), Int32Ty},
                false);
            Constant *GetTaintFn = M.getOrInsertFunction("__afl_taint_load", GetTaintTy);
            
            Value *Op1Tag = TaintIRB.CreateCall(GetTaintFn, {
                TaintIRB.CreateBitCast(Op1, PointerType::get(Int8Ty, 0)),
                ConstantInt::get(Int32Ty, Op1->getType()->getPrimitiveSizeInBits() / 8)
            });
            Value *Op2Tag = TaintIRB.CreateCall(GetTaintFn, {
                TaintIRB.CreateBitCast(Op2, PointerType::get(Int8Ty, 0)),
                ConstantInt::get(Int32Ty, Op2->getType()->getPrimitiveSizeInBits() / 8)
            });
            
            /* [修改] 参数改为 Int32Ty */
            FunctionType *CheckTaintWithTagsTy = FunctionType::get(
                Type::getVoidTy(C),
                {Int32Ty, Int32Ty, Int32Ty},
                false);
            Constant *CheckTaintWithTagsFn = M.getOrInsertFunction("__afl_check_taint_with_tags", CheckTaintWithTagsTy);
            
            TaintIRB.CreateCall(CheckTaintWithTagsFn, {
                ConstantInt::get(Int32Ty, cmp_id),
                Op1Tag,
                Op2Tag
            });

          }

          if (auto *Switch = dyn_cast<SwitchInst>(&I)) {
            unsigned int cmp_id = cmp_id_counter++;
            if (cmp_id < 4096) {
              Value *Cond = Switch->getCondition();
              FunctionType *CheckTaintTy = FunctionType::get(
                  Type::getVoidTy(C),
                  {Int32Ty, PointerType::get(Int8Ty, 0), PointerType::get(Int8Ty, 0)},
                  false);
              Constant *CheckTaintFn = M.getOrInsertFunction("__afl_check_taint", CheckTaintTy);
              IRBuilder<> TaintIRB(&I);
              Value *CondPtr = TaintIRB.CreateBitCast(Cond, PointerType::get(Int8Ty, 0));
              TaintIRB.CreateCall(CheckTaintFn, {
                  ConstantInt::get(Int32Ty, cmp_id),
                  CondPtr,
                  ConstantPointerNull::get(PointerType::get(Int8Ty, 0))
              });
            }
          }

          if (auto *Call = dyn_cast<CallInst>(&I)) {
            Function *Callee = Call->getCalledFunction();
            if (!Callee) continue;
            StringRef FnName = Callee->getName();
            
            /* [修改] 使用 getNumArgOperands() 替代 arg_size() 以兼容旧版 LLVM */
            if ((FnName == "memcmp" || FnName == "strcmp" || 
                 FnName == "strncmp" || FnName == "strcasecmp" ||
                 FnName == "strncasecmp" || FnName == "bcmp") && 
                 Call->getNumArgOperands() >= 2) {
              
              unsigned int cmp_id = cmp_id_counter++;
              if (cmp_id < 4096) {
                FunctionType *CheckTaintTy = FunctionType::get(
                    Type::getVoidTy(C),
                    {Int32Ty, PointerType::get(Int8Ty, 0), PointerType::get(Int8Ty, 0)},
                    false);
                Constant *CheckTaintFn = M.getOrInsertFunction("__afl_check_taint", CheckTaintTy);
                IRBuilder<> TaintIRB(&I);
                TaintIRB.CreateCall(CheckTaintFn, {
                    ConstantInt::get(Int32Ty, cmp_id),
                    TaintIRB.CreateBitCast(Call->getArgOperand(0), PointerType::get(Int8Ty, 0)),
                    TaintIRB.CreateBitCast(Call->getArgOperand(1), PointerType::get(Int8Ty, 0))
                });
              }
            }

            if (FnName == "recv" || FnName == "read" || FnName == "recvfrom" ||
                FnName == "recvmsg" || FnName == "readv") {
              
              FunctionType *TaintSourceTy = FunctionType::get(
                  Type::getVoidTy(C),
                  {PointerType::get(Int8Ty, 0), Int32Ty},
                  false);
              Constant *TaintSourceFn = M.getOrInsertFunction("__afl_taint_source", TaintSourceTy);
              
              IRBuilder<> TaintIRB(&I);
              TaintIRB.SetInsertPoint(&I);
              TaintIRB.SetInsertPoint(I.getNextNode());
              
              /* [修改] 兼容旧版 */
              if (Call->getNumArgOperands() >= 2) {
                Value *Buf = Call->getArgOperand(1);
                Value *Len = Call->getArgOperand(2);
                TaintIRB.CreateCall(TaintSourceFn, {
                    TaintIRB.CreateBitCast(Buf, PointerType::get(Int8Ty, 0)),
                    TaintIRB.CreateZExtOrTrunc(Len, Int32Ty)
                });
              }
            }
          }

          if (auto *Load = dyn_cast<LoadInst>(&I)) {
            if (taint_enabled) {
              /* [修改] Int32Ty */
              FunctionType *TaintLoadTy = FunctionType::get(
                  Int32Ty,
                  {PointerType::get(Int8Ty, 0), Int32Ty},
                  false);
              Constant *TaintLoadFn = M.getOrInsertFunction("__afl_taint_load", TaintLoadTy);
              
              IRBuilder<> TaintIRB(&I);
              TaintIRB.SetInsertPoint(&I);
              TaintIRB.SetInsertPoint(I.getNextNode());
              
              Value *Ptr = Load->getPointerOperand();
              Type *LoadTy = Load->getType();
              unsigned size = LoadTy->getPrimitiveSizeInBits() / 8;
              if (size == 0) size = 1;
              
              Value *Tag = TaintIRB.CreateCall(TaintLoadFn, {
                  TaintIRB.CreateBitCast(Ptr, PointerType::get(Int8Ty, 0)),
                  ConstantInt::get(Int32Ty, size)
              });
              
              /* [修改] Int32Ty */
              FunctionType *TaintStoreTy = FunctionType::get(
                  Type::getVoidTy(C),
                  {PointerType::get(Int8Ty, 0), Int32Ty, Int32Ty},
                  false);
              Constant *TaintStoreFn = M.getOrInsertFunction("__afl_taint_store", TaintStoreTy);
              
              TaintIRB.CreateCall(TaintStoreFn, {
                  TaintIRB.CreateBitCast(Load, PointerType::get(Int8Ty, 0)),
                  ConstantInt::get(Int32Ty, size),
                  Tag
              });
            }
          }

          if (auto *Store = dyn_cast<StoreInst>(&I)) {
            if (taint_enabled) {
              Value *Val = Store->getValueOperand();
              Value *Ptr = Store->getPointerOperand();
              
              /* [修改] Int32Ty */
              FunctionType *TaintLoadTy = FunctionType::get(
                  Int32Ty,
                  {PointerType::get(Int8Ty, 0), Int32Ty},
                  false);
              Constant *TaintLoadFn = M.getOrInsertFunction("__afl_taint_load", TaintLoadTy);
              
              IRBuilder<> TaintIRB(&I);
              Type *ValTy = Val->getType();
              unsigned size = ValTy->getPrimitiveSizeInBits() / 8;
              if (size == 0) size = 1;
              
              Value *Tag = TaintIRB.CreateCall(TaintLoadFn, {
                  TaintIRB.CreateBitCast(Val, PointerType::get(Int8Ty, 0)),
                  ConstantInt::get(Int32Ty, size)
              });
              
              /* [修改] Int32Ty */
              FunctionType *TaintStoreTy = FunctionType::get(
                  Type::getVoidTy(C),
                  {PointerType::get(Int8Ty, 0), Int32Ty, Int32Ty},
                  false);
              Constant *TaintStoreFn = M.getOrInsertFunction("__afl_taint_store", TaintStoreTy);
              
              TaintIRB.CreateCall(TaintStoreFn, {
                  TaintIRB.CreateBitCast(Ptr, PointerType::get(Int8Ty, 0)),
                  ConstantInt::get(Int32Ty, size),
                  Tag
              });
            }
          }

          if (taint_enabled) {
            if (isa<BinaryOperator>(&I)) {
              BinaryOperator *BO = cast<BinaryOperator>(&I);
              if (BO->getOpcode() == Instruction::Add ||
                  BO->getOpcode() == Instruction::Sub ||
                  BO->getOpcode() == Instruction::Mul ||
                  BO->getOpcode() == Instruction::And ||
                  BO->getOpcode() == Instruction::Or ||
                  BO->getOpcode() == Instruction::Xor) {
                
                /* [修改] Int32Ty */
                FunctionType *TaintLoadTy = FunctionType::get(
                    Int32Ty,
                    {PointerType::get(Int8Ty, 0), Int32Ty},
                    false);
                Constant *TaintLoadFn = M.getOrInsertFunction("__afl_taint_load", TaintLoadTy);
                
                /* [修改] Int32Ty */
                FunctionType *TaintPropTy = FunctionType::get(
                    Int32Ty,
                    {Int32Ty, Int32Ty},
                    false);
                Constant *TaintPropFn = M.getOrInsertFunction("__afl_taint_propagate", TaintPropTy);
                
                IRBuilder<> TaintIRB(&I);
                TaintIRB.SetInsertPoint(&I);
                TaintIRB.SetInsertPoint(I.getNextNode());
                
                Value *Op1 = BO->getOperand(0);
                Value *Op2 = BO->getOperand(1);
                
                unsigned size1 = Op1->getType()->getPrimitiveSizeInBits() / 8;
                unsigned size2 = Op2->getType()->getPrimitiveSizeInBits() / 8;
                if (size1 == 0) size1 = 1;
                if (size2 == 0) size2 = 1;
                
                Value *Tag1 = TaintIRB.CreateCall(TaintLoadFn, {
                    TaintIRB.CreateBitCast(Op1, PointerType::get(Int8Ty, 0)),
                    ConstantInt::get(Int32Ty, size1)
                });
                
                Value *Tag2 = TaintIRB.CreateCall(TaintLoadFn, {
                    TaintIRB.CreateBitCast(Op2, PointerType::get(Int8Ty, 0)),
                    ConstantInt::get(Int32Ty, size2)
                });
                
                Value *ResultTag = TaintIRB.CreateCall(TaintPropFn, {Tag1, Tag2});
                
                /* [修改] Int32Ty */
                FunctionType *TaintStoreTy = FunctionType::get(
                    Type::getVoidTy(C),
                    {PointerType::get(Int8Ty, 0), Int32Ty, Int32Ty},
                    false);
                Constant *TaintStoreFn = M.getOrInsertFunction("__afl_taint_store", TaintStoreTy);
                
                unsigned result_size = BO->getType()->getPrimitiveSizeInBits() / 8;
                if (result_size == 0) result_size = 1;
                
                TaintIRB.CreateCall(TaintStoreFn, {
                    TaintIRB.CreateBitCast(BO, PointerType::get(Int8Ty, 0)),
                    ConstantInt::get(Int32Ty, result_size),
                    ResultTag
                });
              }
            }
          }

        }
      }

      inst_blocks++;
    }

  if (!be_quiet) {
    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);
  }

  if (auto_dict_enabled) dumpAutoDictIfRequested();

  return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);