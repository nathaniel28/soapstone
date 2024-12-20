#!/bin/python3

import sys

stmts = []
with open("store.stmts", "r") as fp:
    for line in fp:
        pt = line[:-1].split(" ", 1)
        if len(pt) != 2:
            print(f"skipping {line}", end="", file=sys.stderr)
            continue
        stmts.append(pt)

print("""// This file was generated by storegen.py
// Do not edit this manually

package main

import "database/sql"

type handlerStmts struct {""")
for s in stmts:
    print(f"\t{s[0]} *sql.Stmt")
print("""}

func (h *handlerStmts) closeStmts() {""")
for s in stmts:
    print(f"""\tif h.{s[0]} != nil {{
\t\th.{s[0]}.Close()
\t}}""")
print("""}

func (h *handlerStmts) prepStmts(db *sql.DB) (err error) {
\tdefer func() {
\t\tif err != nil {
\t\t\th.closeStmts()
\t\t}
\t}()""")
for s in stmts:
    print(f"""\th.{s[0]}, err = db.Prepare({s[1]})
\tif err != nil {{
\t\treturn
\t}}""")
print("""\treturn
}""")
