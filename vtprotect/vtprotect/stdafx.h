#pragma once
#define BYTE unsigned char



#ifdef __cplusplus
extern "C" {
#endif
#include <Ntifs.h>
#include <ntddk.h> 
#include <ntimage.h>

#ifdef __cplusplus
}
#endif

#define Log(mes,val) {{KdPrint(("[vtprotect] %-40s [%p]\n",mes,val));}}