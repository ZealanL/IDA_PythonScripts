# GetAllFuncVtableInfo
# PURPOSE: Find all reversed functions that are virtual, print out their table name and inex
# OUTPUT FORMAT: "funcName=tableName=indexInt"
# NOTE: Some functions might have multiple vtable references, these will be IGNORED

import idc
import idautils

# Get segment object from address in the segment
def GetSegment(ea):
    for s in idautils.Segments():
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)
        if (start <= ea and end >= ea):
            return s
    
    return None

# Get a function's SINGLE vtable reference address
# Returns 0 if func is not virtual
def GetFuncVirtualRef(func):
    xrefs = list(idautils.XrefsTo(func.start_ea))
    
    if len(xrefs) != 1:
        return 0
    
    xref = xrefs[0]
    if (xref.frm is None):
        return 0
    
    xrefSeg = GetSegment(xref.frm)

    segName = idc.get_segm_name(xrefSeg)
    if (segName != ".rdata"):
        return 0
    else: 
        return xref.frm

def Clean(s):
    # Just in case
    return s.replace("\n", "_").replace("\r", "_").replace("=", "_")

def CleanVTableName(s):
    return Clean(s).replace("::`vftable'", "").replace("const ", "")

##########################################

# MAIN AREA

for ea in Functions():
    func = ida_funcs.get_func(ea)
    
    if not (func.flags & 0x10000):
        continue # Not lumina function
        
    if (func.flags & idc.FUNC_LIB):
        continue # Dont want lib funcs (just in case some doofus uploads them to the lumina server)
    
    funcName = ida_funcs.get_func_name(ea)
    demangledName = ida_name.demangle_name(funcName, idc.INF_LONG_DN)
    
    if demangledName is not None:
        funcName = demangledName
        
    if ("sub_" in funcName):
        continue # Not properly named lol

    vtableRef = GetFuncVirtualRef(func)
    if (vtableRef == 0):
        continue
                
    addr = vtableRef
    while (addr >= seg.start_ea):
        comment = get_name(addr, False)
        if (comment is not None) and (len(comment) > 0):
            dName = ida_name.demangle_name(comment, idc.INF_LONG_DN)
            if (dName is not None) and ("`vftable'" in dName):
            
                index = (vtableRef - addr) / 4
                if (index != int(index)):
                    break # This should NEVER happen
                    
                print(Clean(funcName) + "=" + CleanVTableName(dName) + "=" + str(int(index)))
                break
                
        addr = idc.prev_head(addr)
