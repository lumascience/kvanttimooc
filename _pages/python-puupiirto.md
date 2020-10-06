---
title: Binääripuun piirtäminen (Python)
hidden: true
---

# Binääripuun piirtäminen (Python)

Binääripuun rakenteen hahmottaminen on vähintäänkin vaikeaa katsomalla koodia, joka muodostaa binääripuun.

Apuun tulee seuraava koodi, joka piirtää binääripuun `turtle`-kirjaston avulla. Kuten muutkin binääripuuhun liittyvät asiat, piirtäminen onnistuu kätevästi rekursion avulla.

```python
from turtle import *
from collections import namedtuple

Node = namedtuple("Node",["left","right"])

def count(node):
    if not node:
        return 0
    return count(node.left)+count(node.right)+1

def draw_tree(node,x,y):
    if not node:
        return
    goto(x,y)
    stamp()
    space = count(node.left.right) if node.left else 0
    draw_tree(node.left,x-(space+1)*30,y-40)
    goto(x,y)
    space = count(node.right.left) if node.right else 0
    draw_tree(node.right,x+(space+1)*30,y-40)
    goto(x,y)

# tässä on binääripuu, joka halutaan piirtää
tree = Node(
    Node(Node(None,None),Node(None,None)),
    Node(Node(None,None),Node(None,None))
)

shape("circle")
draw_tree(tree,0,0)
done()                                                                    
```
