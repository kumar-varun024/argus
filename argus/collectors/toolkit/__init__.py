"""Shared, dependency-light building blocks for collectors (enums, and later
prober/payload/analysis bases). Modules here must import only stdlib and other
toolkit modules — never a concrete collector or the collectors package — so they
are safe to import during ``argus.collectors`` package initialization.
"""
