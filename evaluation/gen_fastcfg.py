#!/usr/bin/env python3
import pygraphviz
import networkx
import angr
import sys
import logging

logging.getLogger('angr').setLevel('CRITICAL')

def main():
    if len(sys.argv) < 2:
        print(f"Usage {sys.argv[0]} path <out>")
        exit(0)

    binfile = sys.argv[1]
    out = f"{binfile}.pdf"

    if len(sys.argv) > 2:
        out = sys.argv[2]

    proj = angr.Project(binfile, load_options={'auto_load_libs': False})

    if 'emulated' in sys.argv[0]:
        print('generating emulated cfg...')
        cfg = proj.analyses.CFGEmulated(keep_state=True)
        graph = networkx.nx_agraph.to_agraph(cfg.graph)

        graph.draw(out, prog='dot')
    else:
        print('generating fast cfg...')
        cfg = proj.analyses.CFGFast()
        graph = networkx.nx_agraph.to_agraph(cfg.graph)

        graph.draw(out, prog='dot')
        
if __name__ == '__main__':
    main()
