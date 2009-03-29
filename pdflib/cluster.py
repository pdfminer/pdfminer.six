#!/usr/bin/env python
import sys


##  binary search
##
def bsearch(objs, v0, v1):
  assert v0 <= v1
  i0 = 0
  i1 = len(objs)-1
  while i0 <= i1:
    i = (i0+i1)/2
    assert 0 <= i and i < len(objs)
    (v, obj) = objs[i]
    if v < v0:
      i0 = i+1
    elif v1 < v:
      i1 = i-1
    else:
      i0 = i
      while 0 < i0:
        (v,_) = objs[i0-1]
        if v < v0: break
        i0 -= 1
      i1 = i
      while i1 < len(objs)-1:
        (v,_) = objs[i1+1]
        if v1 < v: break
        i1 += 1
      return [ obj for (_,obj) in objs[i0:i1+1] ]
  return []


##  Plane
##
class Plane(object):

  def __init__(self):
    self.xobjs = []
    self.yobjs = []
    return

  def add(self, (x0,y0,x1,y1), obj):
    self.xobjs.append((x0, obj))
    self.xobjs.append((x1, obj))
    self.yobjs.append((y0, obj))
    self.yobjs.append((y1, obj))
    return

  def finish(self):
    self.xobjs.sort()
    self.yobjs.sort()
    return

  def find(self, (x0,y0,x1,y1)):
    xobjs = set(bsearch(self.xobjs, x0, x1))
    yobjs = set(bsearch(self.yobjs, y0, y1))
    objs = xobjs.intersection(yobjs)
    return objs


##  ClusterSet
##
class ClusterSet(object):

  def __init__(self):
    self.clusters = {}
    return

  def add(self, obj):
    self.clusters[obj] = (obj,)
    return

  def merge(self, objs):
    allobjs = set(objs)
    for obj in objs:
      if obj in self.clusters:
        allobjs.update(self.clusters[obj])
    c = tuple(allobjs)
    for obj in allobjs:
      self.clusters[obj] = c
    return

  def finish(self):
    return set(self.clusters.itervalues())


def cluster_pageobjs(objs, ratio):
  idx = dict( (obj,i) for (i,obj) in enumerate(objs) )
  plane = Plane()
  for obj in objs:
    plane.add(obj.bbox, obj)
  plane.finish()
  cset = ClusterSet()
  for obj in objs:
    (bx0,by0,bx1,by1) = obj.bbox
    margin = abs(obj.fontsize * ratio)
    x0 = min(bx0,bx1)
    y0 = min(by0,by1)
    x1 = max(bx0,bx1)
    y1 = max(by0,by1)
    found = plane.find((x0-margin, y0-margin, x1+margin, y1+margin))
    if len(found) == 1:
      cset.add(found.pop())
    else:
      cset.merge(found)
  clusters = sorted(cset.finish(), key=lambda objs: idx[objs[0]])
  r = []
  for objs in clusters:
    objs = sorted(objs, key=lambda obj: idx[obj])
    h = v = 0
    (bx0,by0,bx1,by1) = objs[0].bbox
    (lx0,ly0,_,_) = objs[0].bbox
    for obj in objs[1:]:
      (x0,y0,x1,y1) = obj.bbox
      if len(obj.text) == 1 and abs(lx0-x0) < abs(ly0-y0):
        v += 1
      else:
        h += 1
      (lx0,ly0) = (x0,y0)
      bx0 = min(bx0, x0)
      bx1 = max(bx1, x1)
      by0 = min(by0, y0)
      by1 = max(by1, y1)
    r.append(((bx0,by0,bx1,by1), h < v, objs))
  return r
