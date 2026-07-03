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
#include <functional>
#include "llvm/ADT/DenseMap.h"

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

  static Function *getDirectCallee(CallInst *Call) {
    if (!Call) return nullptr;
    Value *Called = Call->getCalledValue();
    if (!Called) return nullptr;
    Called = Called->stripPointerCasts();
    return dyn_cast<Function>(Called);
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

  FunctionType *TaintLoadTy = FunctionType::get(
      Int32Ty, {PointerType::get(Int8Ty, 0), Int32Ty}, false);
  FunctionCallee TaintLoadFn = M.getOrInsertFunction("__afl_taint_load", TaintLoadTy);

  FunctionType *TaintStoreTy = FunctionType::get(
      Type::getVoidTy(C),
      {PointerType::get(Int8Ty, 0), Int32Ty, Int32Ty},
      false);
  FunctionCallee TaintStoreFn = M.getOrInsertFunction("__afl_taint_store", TaintStoreTy);

  FunctionType *TaintPropTy = FunctionType::get(
      Int32Ty, {Int32Ty, Int32Ty}, false);
  FunctionCallee TaintPropFn = M.getOrInsertFunction("__afl_taint_propagate", TaintPropTy);

  FunctionType *CheckTaintTy = FunctionType::get(
      Type::getVoidTy(C), {Int32Ty, Int32Ty, Int32Ty}, false);
  FunctionCallee CheckTaintFn =
      M.getOrInsertFunction("__afl_check_taint_with_tags", CheckTaintTy);

  FunctionType *TaintSourceTy = FunctionType::get(
      Type::getVoidTy(C), {PointerType::get(Int8Ty, 0), Int32Ty}, false);
  FunctionCallee TaintSourceFn =
      M.getOrInsertFunction("__afl_taint_source", TaintSourceTy);
  FunctionCallee TaintSourceNetFn =
      M.getOrInsertFunction("__afl_taint_source_net", TaintSourceTy);

  FunctionType *TaintSourceIovTy = FunctionType::get(
      Type::getVoidTy(C), {PointerType::get(Int8Ty, 0), Int32Ty, Int32Ty}, false);
  FunctionCallee TaintSourceIovFn =
      M.getOrInsertFunction("__afl_taint_source_iov", TaintSourceIovTy);

  FunctionType *TaintSourceMsgTy = FunctionType::get(
      Type::getVoidTy(C), {PointerType::get(Int8Ty, 0), Int32Ty}, false);
  FunctionCallee TaintSourceMsgFn =
      M.getOrInsertFunction("__afl_taint_source_msghdr", TaintSourceMsgTy);

  FunctionType *TaintMemcpyTy = FunctionType::get(
      Type::getVoidTy(C), {PointerType::get(Int8Ty, 0), PointerType::get(Int8Ty, 0), Int32Ty}, false);
  FunctionCallee TaintMemcpyFn =
      M.getOrInsertFunction("__afl_taint_memcpy", TaintMemcpyTy);

  FunctionType *CheckTaintBufTy = FunctionType::get(
      Type::getVoidTy(C), {Int32Ty, PointerType::get(Int8Ty, 0), Int32Ty}, false);
  FunctionCallee CheckTaintBufFn =
      M.getOrInsertFunction("__afl_check_taint_buf", CheckTaintBufTy);

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

        DenseMap<Value*, Value*> value_tags;
        std::function<Value*(Value*, IRBuilder<>&)> buildTagForValue;
        buildTagForValue = [&](Value* V, IRBuilder<> &B) -> Value* {
          if (!V) return ConstantInt::get(Int32Ty, 0);

          DenseMap<Value*, Value*>::iterator it = value_tags.find(V);
          if (it != value_tags.end()) return it->second;

          if (isa<Constant>(V)) {
            return ConstantInt::get(Int32Ty, 0);
          }

          if (auto *LI = dyn_cast<LoadInst>(V)) {
            Value *Ptr = LI->getPointerOperand();
            Type *LoadTy = LI->getType();
            unsigned size = LoadTy->getPrimitiveSizeInBits() / 8;
            if (!size) size = 1;
            Value *Tag = B.CreateCall(TaintLoadFn, {
                B.CreateBitCast(Ptr, PointerType::get(Int8Ty, 0)),
                ConstantInt::get(Int32Ty, size)
            });
            value_tags[V] = Tag;
            return Tag;
          }

          if (auto *BO = dyn_cast<BinaryOperator>(V)) {
            unsigned op = BO->getOpcode();
            if (op == Instruction::Add || op == Instruction::Sub ||
                op == Instruction::Mul || op == Instruction::And ||
                op == Instruction::Or  || op == Instruction::Xor) {
              Value *T1 = buildTagForValue(BO->getOperand(0), B);
              Value *T2 = buildTagForValue(BO->getOperand(1), B);
              Value *HasT1 = B.CreateICmpNE(T1, ConstantInt::get(Int32Ty, 0));
              Value *HasT2 = B.CreateICmpNE(T2, ConstantInt::get(Int32Ty, 0));
              Value *HasAny = B.CreateOr(HasT1, HasT2);
              Value *PropTag = B.CreateCall(TaintPropFn, {T1, T2});
              Value *Tag = B.CreateSelect(
                  HasAny,
                  PropTag,
                  ConstantInt::get(Int32Ty, 0));
              value_tags[V] = Tag;
              return Tag;
            }
          }

          if (auto *CI = dyn_cast<CastInst>(V)) {
            return buildTagForValue(CI->getOperand(0), B);
          }

          if (V->getType()->isPointerTy()) {
            Value *Tag = B.CreateCall(TaintLoadFn, {
                B.CreateBitCast(V, PointerType::get(Int8Ty, 0)),
                ConstantInt::get(Int32Ty, 1)
            });
            value_tags[V] = Tag;
            return Tag;
          }

          return ConstantInt::get(Int32Ty, 0);
        };

        for (auto &I : BB) {

          if (auto *ICmp = dyn_cast<ICmpInst>(&I)) {

            bool is_candidate = false;
            for (User *U : ICmp->users()) {
              if (auto *Br = dyn_cast<BranchInst>(U)) {
                if (Br->isConditional() && Br->getCondition() == ICmp) {
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

            Instruction *Next = I.getNextNode();
            if (!Next) continue;
            IRBuilder<> TaintIRB(Next);

            Value *Op1Tag = buildTagForValue(Op1, TaintIRB);
            Value *Op2Tag = buildTagForValue(Op2, TaintIRB);

            TaintIRB.CreateCall(CheckTaintFn, {
                ConstantInt::get(Int32Ty, cmp_id),
                Op1Tag,
                Op2Tag
            });

          }

          if (auto *Switch = dyn_cast<SwitchInst>(&I)) {
            unsigned int cmp_id = cmp_id_counter++;
            if (cmp_id < 4096) {
              Value *Cond = Switch->getCondition();
              IRBuilder<> TaintIRB(&I);
              Value *CondTag = buildTagForValue(Cond, TaintIRB);
              TaintIRB.CreateCall(CheckTaintFn, {
                  ConstantInt::get(Int32Ty, cmp_id),
                  CondTag,
                  ConstantInt::get(Int32Ty, 0)
              });
            }
          }

          if (auto *Call = dyn_cast<CallInst>(&I)) {
            Function *Callee = getDirectCallee(Call);
            if (!Callee) continue;
            StringRef FnName = Callee->getName();
            bool IsLlvmMemcpy = FnName.startswith("llvm.memcpy") || FnName.startswith("llvm.memmove");
            
            if ((FnName == "memcmp" || FnName == "strcmp" || 
                 FnName == "strncmp" || FnName == "strcasecmp" ||
                 FnName == "strncasecmp" || FnName == "bcmp") && 
                 Call->getNumArgOperands() >= 2) {

              bool is_candidate = false;
              for (User *U : Call->users()) {
                if (auto *CmpUse = dyn_cast<ICmpInst>(U)) {
                  for (User *CU : CmpUse->users()) {
                    if (auto *Br = dyn_cast<BranchInst>(CU)) {
                      if (Br->isConditional() && Br->getCondition() == CmpUse) {
                        is_candidate = true;
                        break;
                      }
                    }
                  }
                }
                if (is_candidate) break;
              }
              if (!is_candidate) continue;
              
              unsigned int cmp_id = cmp_id_counter++;
              if (cmp_id < 4096) {
                IRBuilder<> TaintIRB(&I);
                Value *Len = ConstantInt::get(Int32Ty, 64);
                if ((FnName == "memcmp" || FnName == "strncmp" ||
                     FnName == "strncasecmp" || FnName == "bcmp") &&
                    Call->getNumArgOperands() >= 3) {
                  Value *RawLen = Call->getArgOperand(2);
                  if (RawLen->getType()->isIntegerTy())
                    Len = TaintIRB.CreateZExtOrTrunc(RawLen, Int32Ty);
                }

                Value *Arg1 = TaintIRB.CreateBitCast(Call->getArgOperand(0), PointerType::get(Int8Ty, 0));
                Value *Arg2 = TaintIRB.CreateBitCast(Call->getArgOperand(1), PointerType::get(Int8Ty, 0));
                TaintIRB.CreateCall(CheckTaintBufFn, {
                    ConstantInt::get(Int32Ty, cmp_id), Arg1, Len
                });
                TaintIRB.CreateCall(CheckTaintBufFn, {
                    ConstantInt::get(Int32Ty, cmp_id), Arg2, Len
                });
              }
            }

            if (FnName == "recv" || FnName == "read" || FnName == "recvfrom") {

              Instruction *Next = I.getNextNode();
              if (!Next) continue;
              IRBuilder<> TaintIRB(Next);

              Value *Buf = nullptr;
              if (Call->getNumArgOperands() >= 3) {
                Buf = Call->getArgOperand(1);
              }

              if (!Buf) continue;

              Value *Ret = Call;
              if (!Ret->getType()->isIntegerTy()) continue;
              Value *Ret32 = TaintIRB.CreateSExtOrTrunc(Ret, Int32Ty);
              Value *HasInput = TaintIRB.CreateICmpSGT(Ret32, ConstantInt::get(Int32Ty, 0));
              Value *SafeLen = TaintIRB.CreateSelect(
                  HasInput, Ret32, ConstantInt::get(Int32Ty, 0));
              FunctionCallee SrcFn = (FnName == "read") ? TaintSourceFn : TaintSourceNetFn;
              TaintIRB.CreateCall(SrcFn, {
                  TaintIRB.CreateBitCast(Buf, PointerType::get(Int8Ty, 0)),
                  SafeLen
              });
            }

            if (FnName == "readv" || FnName == "recvmsg") {
              Instruction *Next = I.getNextNode();
              if (!Next) continue;
              IRBuilder<> TaintIRB(Next);

              Value *Ret = Call;
              if (!Ret->getType()->isIntegerTy()) continue;
              Value *Ret32 = TaintIRB.CreateSExtOrTrunc(Ret, Int32Ty);
              Value *HasInput = TaintIRB.CreateICmpSGT(Ret32, ConstantInt::get(Int32Ty, 0));
              Value *SafeLen = TaintIRB.CreateSelect(
                  HasInput, Ret32, ConstantInt::get(Int32Ty, 0));

              if (FnName == "readv" && Call->getNumArgOperands() >= 3) {
                TaintIRB.CreateCall(TaintSourceIovFn, {
                    TaintIRB.CreateBitCast(Call->getArgOperand(1), PointerType::get(Int8Ty, 0)),
                    TaintIRB.CreateZExtOrTrunc(Call->getArgOperand(2), Int32Ty),
                    SafeLen
                });
              } else if (FnName == "recvmsg" && Call->getNumArgOperands() >= 2) {
                TaintIRB.CreateCall(TaintSourceMsgFn, {
                    TaintIRB.CreateBitCast(Call->getArgOperand(1), PointerType::get(Int8Ty, 0)),
                    SafeLen
                });
              }
            }

            if ((FnName == "memcpy" || FnName == "memmove" || IsLlvmMemcpy) &&
                Call->getNumArgOperands() >= 3) {
              Instruction *Next = I.getNextNode();
              if (!Next) continue;
              IRBuilder<> TaintIRB(Next);
              Value *Len = Call->getArgOperand(2);
              if (!Len->getType()->isIntegerTy()) continue;
              TaintIRB.CreateCall(TaintMemcpyFn, {
                  TaintIRB.CreateBitCast(Call->getArgOperand(0), PointerType::get(Int8Ty, 0)),
                  TaintIRB.CreateBitCast(Call->getArgOperand(1), PointerType::get(Int8Ty, 0)),
                  TaintIRB.CreateZExtOrTrunc(Len, Int32Ty)
              });
            }
          }

          if (auto *Load = dyn_cast<LoadInst>(&I)) {
            Instruction *Next = I.getNextNode();
            if (!Next) continue;
            IRBuilder<> TaintIRB(Next);
            Value *Ptr = Load->getPointerOperand();
            unsigned size = Load->getType()->getPrimitiveSizeInBits() / 8;
            if (!size) size = 1;
            Value *Tag = TaintIRB.CreateCall(TaintLoadFn, {
                TaintIRB.CreateBitCast(Ptr, PointerType::get(Int8Ty, 0)),
                ConstantInt::get(Int32Ty, size)
            });
            value_tags[Load] = Tag;
          }

          if (auto *Store = dyn_cast<StoreInst>(&I)) {
            if (taint_enabled) {
              Value *Val = Store->getValueOperand();
              Value *Ptr = Store->getPointerOperand();

              IRBuilder<> TaintIRB(&I);
              Type *ValTy = Val->getType();
              unsigned size = ValTy->getPrimitiveSizeInBits() / 8;
              if (size == 0) size = 1;

              Value *Tag = buildTagForValue(Val, TaintIRB);
              TaintIRB.CreateCall(TaintStoreFn, {
                  TaintIRB.CreateBitCast(Ptr, PointerType::get(Int8Ty, 0)),
                  ConstantInt::get(Int32Ty, size),
                  Tag
              });
            }
          }

          if (taint_enabled && isa<BinaryOperator>(&I)) {
            BinaryOperator *BO = cast<BinaryOperator>(&I);
            unsigned op = BO->getOpcode();
            if (op == Instruction::Add || op == Instruction::Sub ||
                op == Instruction::Mul || op == Instruction::And ||
                op == Instruction::Or  || op == Instruction::Xor) {
              Instruction *Next = I.getNextNode();
              if (!Next) continue;
              IRBuilder<> TaintIRB(Next);
              Value *T1 = buildTagForValue(BO->getOperand(0), TaintIRB);
              Value *T2 = buildTagForValue(BO->getOperand(1), TaintIRB);
              Value *HasT1 = TaintIRB.CreateICmpNE(T1, ConstantInt::get(Int32Ty, 0));
              Value *HasT2 = TaintIRB.CreateICmpNE(T2, ConstantInt::get(Int32Ty, 0));
              Value *HasAny = TaintIRB.CreateOr(HasT1, HasT2);
              Value *PropTag = TaintIRB.CreateCall(TaintPropFn, {T1, T2});
              value_tags[BO] = TaintIRB.CreateSelect(
                  HasAny, PropTag, ConstantInt::get(Int32Ty, 0));
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