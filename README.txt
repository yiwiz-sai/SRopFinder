you have to setup "distorm" python package first , it's a powerful disassembler library

if __name__=='__main__':
    code=open('distorm3.dll', 'rb').read()
    
    #===================show line number===============
    g_srop_linenumber=5
    
    #===================search instruction=============
    g_regular_expression=re.compile('RET')
    #g_regular_expression=re.compile('CALL.*[ ]EAX')
    #g_regular_expression=re.compile('POP.*[ ]ESI')
    g_srop_discernfunc=SROP_discern_instruction
    SROP_findinstruction_at_va(0x10000000, code[0x400:], 0xa200)
    
    sys.exit(0)
    #===================search hex=====================
    g_hex='C3'
    g_srop_discernfunc=SROP_discern_hex
    SROP_findinstruction_at_va(0x10000000, code[0x400:], 0xa200)
    
    sys.exit(0)
    
   
