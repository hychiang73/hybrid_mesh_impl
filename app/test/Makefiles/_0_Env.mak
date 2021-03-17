
# 目前全面使用預設的 CXX 來編譯 , 也就是 g++

CXXFLAGS = -g -Wall -std=c++11
# 靜態連結的執行檔是給沒裝 pdcurses library 的電腦用的
#CXXFLAGS = -g -Wall -static

SRC_DIR = src
# For g++
INC = -Iinclude
# For g++, link 時要放在 .o 後面才有用喔
# LIB += -lpdcurses
LIB += -lpthread

#
# 定義tab，輸出tab在windows與linux要用不同的語法
#
MyNull =
ifeq ($(MY_OS),WIN)
	MyTab =$(MyNull)	$(MyNull)
else
	MyTab = '\t'
endif

# 使用 wildcard 函式馬上攤開所有的 .cpp 與 .c
src_cpp = $(notdir $(wildcard $(SRC_DIR)/*.cpp))
src_c   = $(notdir $(wildcard $(SRC_DIR)/*.c))
src_all = $(src_cpp) $(src_c)

# 以所有的 .cpp 與 .c 命名 .o 檔
obj_cpp = $(src_cpp:.cpp=.o)
obj_c   = $(src_c:.c=.o)
obj_all = $(obj_cpp) $(obj_c)

# 以所有的 .cpp 與 .c 命名個別的 Makefile
mfile_cpp = $(src_cpp:.cpp=.d)
mfile_c   = $(src_c:.c=.d)
mfile_all = $(mfile_cpp) $(mfile_c)

# 個別 Makefile 的放置資料夾
mfile_dir = Makefiles
# .o檔的放置資料夾
build_dir = build
# 把所有的 .o檔 加上 放置資料夾的路徑
OBJS = $(patsubst %,$(build_dir)/%,$(obj_all))


# 為這些中間檔加入 Make 的"依賴目標"描掃路徑 才不會每次都重新產生
vpath %.d $(mfile_dir)
vpath %.o $(build_dir)

