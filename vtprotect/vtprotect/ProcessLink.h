#pragma once
#include "stdafx.h"
extern bool IsProtect(PEPROCESS process);
extern  bool IsProtect(HANDLE pid);
extern void AddLink(PEPROCESS process, HANDLE pid);
extern void DeleteLink();