#!/usr/bin/env node
// JavaScript port of the Cognis scan logic — same rules, same shape.
import { readdirSync, statSync, readFileSync } from "fs";
import { join } from "path";
const RULES = [["GEN-001","high","TODO"],["GEN-002","medium","FIXME"],["GEN-003","low","XXX"]];
function walk(p){ try{ return statSync(p).isDirectory()
  ? readdirSync(p).flatMap(f=>walk(join(p,f))) : [p]; }catch{ return []; } }
export function scan(target){
  const findings=[];
  for(const f of walk(target)){
    let t=""; try{ t=readFileSync(f,"utf8"); }catch{ continue; }
    for(const [id,sev,needle] of RULES) if(t.includes(needle)) findings.push({id,sev,where:f});
  }
  return { tool:"c2detect", findings, score: findings.length };
}
if(import.meta.url===`file://${process.argv[1]}`){
  console.log(JSON.stringify(scan(process.argv[2]||"."),null,2));
}
