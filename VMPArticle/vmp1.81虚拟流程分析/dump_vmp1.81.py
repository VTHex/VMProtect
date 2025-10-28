import od2_trace_parser

handler_map = {
    0x0404000: 'vAdd4',
    0x0404041: 'vNor2',
    0x0404058: 'vPopReg4',
    0x0404069: 'vReadMemSs4',
    0x0404077: 'vShr4',
    0x040408E: 'vRet',
    0x040449C: 'vReadMemSs1',
    0x04044AE: 'vWriteMemDs1',
    0x04044BE: 'vPushImmSx2',
    0x04044D0: 'vPushReg1',
    0x04044E4: 'vPushImm1',
    0x04044F6: 'vWriteMemDs2',
    0x0404508: 'vReadMemDs2',
    0x040451A: 'vNor4',
    0x0404532: 'vPopBP',
    0x040453B: 'vPushImmSx1',
    0x040454E: 'vShr2',
    0x0404568: 'vPopReg1',
    0x040457C: 'vPopEBP',
    0x0404584: 'vReadMemDs4',
    0x0404591: 'vNor1',
    0x04045AF: 'vPushReg4',
    0x04045C0: 'vShl1',
    0x04045D8: 'vWriteMemSs4',
    0x04045E9: 'vPushReg2',
    0x04045FC: 'vAdd2',
    0x0404610: 'vShrd4',
    0x040462B: 'vPushImm4',
    0x040463B: 'vPushBP',
    0x040464D: 'vPushImm2',
    0x040465F: 'vReadMemDs1',
    0x0404670: 'vWriteMemDs4',
    0x0404680: 'vShr1',
    0x0404698: 'vShl2',
    0x04046B2: 'vPushEBP',
    0x04046BF: 'vShld4',
    0x04046DA: 'vPopReg2',
    0x04046EF: 'vShl4',
    0x0404706: 'vWriteMemSs2',
    0x0404719: 'vReadMemSs2',
    0x040475E: 'vWriteMemSs1',
    0x040476F: 'vAdd1'
}



if __name__ == '__main__':

    traces = od2_trace_parser.parse_od2_trace('trace.txt')

    for t in traces:
        if t.address in handler_map:
            pcode =  handler_map[t.address]
            if pcode == 'vPopReg4' or pcode == 'vPushReg4':
                print '%s\tR%d' % (pcode, (t.registers['EAX'] & 0x3C)/4)
            elif pcode == 'vPushImm4' or pcode == 'vPushImmSx2':
                print '%s\t%#x' % (pcode, t.next_trace(3).registers['EAX'])
            else:
                print pcode