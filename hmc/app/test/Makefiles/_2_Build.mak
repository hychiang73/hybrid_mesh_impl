

# 載入公用的變數
include _0_Env.mak

# 載入個別 .o 檔的 Makefile
include $(mfile_all)

.PHONY: Build_All
Build_All: a.out

# 將所有 .o 檔與 Library Link 成執行檔
a.out: $(obj_all)
	$(CXX) $(INC) $(CXXFLAGS) $(OBJS) -o a.out $(LIB)
