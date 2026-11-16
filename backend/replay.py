"""In-memory playback of previously exported observations; never controls routers."""
import asyncio, json
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
class Replay:
    def __init__(self):
        self.scenario='sample'; self.records=[]; self.index=0; self.remaining=0.0; self.speed=60.0; self.playing=False; self.task=None
    def load(self, scenario=None):
        if scenario is not None: self.scenario=scenario
        paths={'sample':'observations.jsonl','youtube-2008':'youtube_2008.jsonl'}
        if self.scenario not in paths: raise ValueError('Unknown replay scenario')
        path=ROOT/'data'/paths[self.scenario]
        self.records=sorted((json.loads(line) for line in path.read_text().splitlines() if line.strip()), key=lambda x:x['timestamp_utc']) if path.exists() else []
        self.index=0; self.remaining=0.0; self.playing=False
    def snapshot(self):
        return {'scenario':self.scenario,'available':bool(self.records),'playing':self.playing,'speed':self.speed,'index':self.index,'total':len(self.records),'current':self.records[self.index-1] if self.index else None,'notice':'Historical observations; no Internet or lab router is changed.'}
    async def run(self):
        while self.playing and self.index<len(self.records):
            while self.playing and self.remaining>0:
                before=asyncio.get_running_loop().time()
                await asyncio.sleep(min(.25,self.remaining/self.speed))
                self.remaining-=max(0,asyncio.get_running_loop().time()-before)*self.speed
            if not self.playing: break
            current=self.records[self.index]; self.index+=1
            if self.index<len(self.records):
                a=datetime.fromisoformat(current['timestamp_utc']).timestamp()
                b=datetime.fromisoformat(self.records[self.index]['timestamp_utc']).timestamp()
                self.remaining=max(0,b-a)
        if self.index>=len(self.records): self.playing=False
    def play(self):
        if not self.records: self.load()
        if not self.records: raise ValueError('No observations available')
        if self.index>=len(self.records): self.index=0; self.remaining=0.0
        if not self.playing:
            self.playing=True; self.task=asyncio.create_task(self.run())
    def pause(self):
        self.playing=False
        if self.task: self.task.cancel(); self.task=None
