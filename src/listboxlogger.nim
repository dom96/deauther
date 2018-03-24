import logging

import tui

type
  ListBoxLogger* = ref object of Logger
    lb*: ListBox

proc newListBoxLogger*(levelThreshold = lvlAll,
                       fmtStr = defaultFmtStr): ListBoxLogger =
  new result
  result.lb = newListBox(
    50, 20,
    initListBoxData(@["Messages"])
  )
  result.fmtStr = fmtStr
  result.levelThreshold = levelThreshold

method log*(logger: ListBoxLogger, level: Level, args: varargs[string, `$`]) =
  if level >= logger.levelThreshold:
    logger.lb.add(@[substituteLog(logger.fmtStr, level, args)])