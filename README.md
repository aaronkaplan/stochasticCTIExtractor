# stochastic_alex
Interface LLMs from within MISP to extract TTPs and threat intel from CTI reports



This RESTful API service accepts markdown text as input. It expects that the text was a CTI report  (some blog post or so ) and cleaned (i.e. no links, advertisement etc in it).
It will then ask an LLM to summarize the CTI report and extract relevant information on threat actors, TTPs, etc. out. 
Finally, it will send the results back to the called (MISP in this case).


## workflow and architecture sketch

![image](https://github.com/aaronkaplan/stochastic_alex/assets/750019/104f793a-80b2-45cd-9fae-594d58212f36)

