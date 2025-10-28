import re
import argparse

def INT16(s):
    try:
        return int(s, 16)
    except:
        return -1

class Trace(object):
    def __init__(self, line):
        """
        Parse Ollydbg 2.0 trace line.
        """
        try:
            mod, addr, disasm, mem_str, reg_str = line.split('\t')
            
            # print line.split('\t')

            self.module = mod
            self.address = INT16(addr)
            self.disasm = disasm           
            self.memorys = {}
            self.registers = {}

            for addr, value in re.findall('\[([0-9A-F]+)\]=([0-9A-F]+)', mem_str):
                self.memorys[INT16(addr)] = INT16(value)
            
            for reg, value in re.findall('([EABCDXSPI]+)=([0-9A-F]+)', reg_str):
                self.registers[reg] = INT16(value)

            self.prev = None
            self.next = None
        except:
            raise Exception('[!] Unknown format: %s' % line)
            

    def __str__(self):
        mem_str = ', '.join(['[%#x]=%#x' % (addr, value) 
            for addr, value in self.memorys.items()])
        
        reg_str = ', '.join(['%s=%#x' % (reg, value) 
            for reg, value in self.registers.items()])
            
        return '%s\t%#x\t%s\t%s\t%s' % (self.module,
            self.address,
            self.disasm,
            mem_str,
            reg_str)

    def __repr__(self):
        return '<Trace %#x %s>' % (self.address, self.disasm)


    def test(self, addr=None, m=None, mv=None, r=None, rv=None):
        if addr:
            if self.address != addr: return False

        if m:
            if m not in self.memorys: return False
        if mv:
            if mv not in self.memorys.values(): return False
        if m and mv:
            if self.memorys[m] != mv : return False

        if r:
            if r not in self.registers: return False
        if rv:
            if rv not in self.registers.values(): return False
        if r and rv:
            if self.registers[r] != rv: return False
        
        return True
    
    def next_trace(self, step=1):
        cur = self
        for i in range(step):
            if cur.next is None: 
                break
            cur = cur.next
        return cur

def parse_od2_trace(filename):
    traces = []
    
    buf = open(filename,'rb').read()
    lines = buf.splitlines()

    prev = None
    for line in lines:
        try:
            t = Trace(line)
            traces.append(t)
            
            if prev:
                t.prev = prev
                prev.next = t
            prev = t
        except:
            pass
    return traces

def search_trace(traces, a=None, m=None, mv=None, r=None, rv=None):
    result = []
    for t in traces:
        if t.test(a, m, mv, r, rv):
            result.append(t)
    return result

def main():
    parser = argparse.ArgumentParser(description='Parser of Ollydbg 2.0 Trace file.')
    parser.add_argument("file", help='Input Ollydbg 2.0 trace file.')
    parser.add_argument("-a", "--address", type=INT16, help='Search instructions at this address.')
    parser.add_argument("-m", "--memory-address", type=INT16)
    parser.add_argument("-mv", "--memory-value", type=INT16)
    parser.add_argument("-r",  "--register-name")
    parser.add_argument("-rv",  "--register-value", type=INT16)
    # return parser

    args = parser.parse_args()

    traces = parse_od2_trace(args.file)

    print '[+] %d traces parsed.' % len(traces)

    print '[+] Search result:'

    result = search_trace(traces, args.address, 
            args.memory_address, args.memory_value, 
            args.register_name, args.register_value)

    for t in result:
        print t 

    print '[+] %d traces found.' % len(result)

if __name__ == '__main__':

    main()
        
   


