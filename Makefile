CLANG ?= clang
# CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g -Wall -c $(CFLAGS)
# CFLAGS := -g $(CFLAGS)
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)
XDP_PROG := xsk_def_xdp_prog_5_3 xsk_def_xdp_prog
PROG_DIR := .
XDP_DIR := $(PROG_DIR)/xdp
SUFFIXES := _bpfel.o _bpfel.go _bpfeb.o _bpfeb.go
XDP_OBJECTS := $(foreach prog,$(XDP_PROG),$(foreach suf,$(SUFFIXES),$(PROG_DIR)/$(prog)$(suf)))

xdp: $(XDP_OBJECTS)

$(XDP_OBJECTS) : $(XDP_DIR)/*.c $(XDP_DIR)/*.h
	@ cd $(PROG_DIR) && go generate -x

clean: 
	@ rm $(XDP_OBJECTS)

