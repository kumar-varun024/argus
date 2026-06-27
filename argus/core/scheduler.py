from typing import Iterable


class Scheduler:

    def run(self, tasks: Iterable):

        for task in tasks:
            yield task
