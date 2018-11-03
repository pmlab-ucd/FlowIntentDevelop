AppInspector
0. Set up a clean TaintDroid environment, with UiDroid_TaintNotify installed (to extract logs from TaintDroid). 
1. Run the exerciser (e.g. UIDroid) to automatically collect sensitive transmissions and the corresponding app-level contexts. 
2. Run TaintDroidLogProcessor to filter app contexts (with the pcaps) who do not generate any sensitive flows.
3. (cd the filtered directory, manually label the app contexts to be 'expected' or not based on the sensitive info transmitted.)
4. Having the labelled contexts, run ContextHandler.py to build ML models.

TrafficAnalyzer
1. 