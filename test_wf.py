#!/usr/bin/python

import yaml
import os
from pprint import pprint
import logging
import snactor.executors
from snactor.loader import load
from snactor.registry import get_actor

WF_PATH = "workflow"
WF_ACTORS_DEF = "workflow.yaml"

def build_path(path_members):
    path = ""

    for member in path_members:
        path = os.path.join(path, member)

    return path


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
load(build_path(["workflow", "actors"]))

# initial data for "static" composer
in_data = {
    "shallow": True,
    "host": "127.0.0.1"
}

workflows = yaml.load(open(WF_ACTORS_DEF))
for workflow in workflows["workflows"]:
    wf_name = workflow["name"]
    for task in workflow["tasks"]:
        #out_data = get_actor(task)().execute(in_data)
        #pprint(out_data)
        pprint(task)

#data = {}
#print get_actor('osversion')().execute(data)
#pprint(data)
