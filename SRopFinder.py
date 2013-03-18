#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI

import os,sys,time
import optparse, re
import distorm3

g_srop_linenumber=0
g_srop_discernfunc=None
g_regular_expression=None
g_hex=None

class InstructionNode(object):
    def __init__(self, va, cur_offset, hexdump, instruction):
        self.cur_offset=cur_offset
        self.va=va
        self.hexdump=hexdump
        self.instruction=instruction
        self.child=None
        self.parents=[]
        pass
    def __repr__(self):
        return "%X:\t%-16s\t%s" % (self.va, self.hexdump, self.instruction)
    
def SROP_discern_instruction(instruction, hex):
    global g_regular_expression

    if g_regular_expression.match(instruction):
        return True
    return False

def SROP_discern_hex(instruction,  hex):
    global g_hex

    if hex==g_hex:
        return True
    return False



def SROP_findinstruction_at_va(baseaddr, code_start, code_size):
    global g_srop_linenumber
    
    instruction_node_map={}
    rop_node_map={}
    
    for offset in xrange(code_size):
        if offset in instruction_node_map:
            continue
        
        try:
            iterable = distorm3.DecodeGenerator(baseaddr+offset, code_start[offset:], distorm3.Decode32Bits)
            parent_node=None
            node_inserted=0
            for (va, size, instruction, hexdump) in iterable:
                hexdump=hexdump.upper()
                #print "%X:\t%-16s\t%s" % (va, hexdump.upper(), instruction)
                cur_offset=va-baseaddr
                node=instruction_node_map.get(cur_offset)
                if not node:
                    node=InstructionNode(va, cur_offset, hexdump, instruction)
                else:
                    node_inserted=1
                    
                if parent_node:
                    node.parents.append(parent_node)
                    parent_node.child=node
                
                parent_node=node
                if node_inserted:
                    break
                
                if g_srop_discernfunc(instruction,hexdump):
                    rop_node_map[cur_offset]=node#whct instruction we need is contained in this node
                
                instruction_node_map[cur_offset]=node
        except:
            pass
    
    SROP_show_result(rop_node_map)
    
def SROP_show_result(rop_node_map):
    def show_rop_node_chain(rop_node_map, n, node, node_chain):
        output=0
        origin_len=len(node_chain)
        if n and node.parents:
            for i in node.parents:
                if (i.cur_offset not in rop_node_map) and (not i.instruction.startswith('DB ')):
                    node_chain=node_chain[:origin_len]
                    node_chain.append(i)
                    show_rop_node_chain(rop_node_map,n-1,  i, node_chain)
                    output=1
        
        if not output:
            #accessing this chain complete
            for i in node_chain[::-1]:
                print i
            print '='*30
    

    l=rop_node_map.items()
    l.sort()
    for offset, node in l:
        show_rop_node_chain(rop_node_map, g_srop_linenumber, node, [node])
    

    
if __name__=='__main__':
    code=open('distorm3.dll', 'rb').read()
    
    #===================show line number===============
    g_srop_linenumber=5
    
    #===================search instruction=============
    g_regular_expression=re.compile('RET')
    #g_regular_expression=re.compile('CALL.*[ ]EAX')
    #g_regular_expression=re.compile('POP.*[ ]ESI')
    g_srop_discernfunc=SROP_discern_instruction
    SROP_findinstruction_at_va(0x10001000, code[0x400:], 0xa200)
    #SROP_findinstruction_at_va(0x10000000, code[0xA100:], 0x200)
    sys.exit(0)
    #===================search hex=====================
    g_hex='C3'
    g_srop_discernfunc=SROP_discern_hex
    SROP_findinstruction_at_va(0x10000000, code[0x400:], 0xa200)
    
    sys.exit(0)
    
    
    
