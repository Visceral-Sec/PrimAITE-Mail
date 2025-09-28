# Disclaimer - `Primaite-Mail` was developed through AI

The creation of this plugin is the result of an an experiment to investigate the feasibility of creating a simple plugin to [`PrimAITE`](github.com/Autonomous-Resilient-Cyber-Defence/PrimAITE) using AI. Any users who install and utilise the `PrimAITE-Mail` plugin are not granted any guarantee of stability, accuracy or usefulness. 

Below is the following conclusions from this experiment that readers may find relevant

- `PrimAITE-Mail` Using [Kiro](https://kiro.dev/) and specifically the **Claude Sonnet 4** model
- Generative AI is most effective at generating unit-tests and integration tests
- The mix of patterns in the original PrimAITE source-code is the biggest source of hallucinations and general coding mistakes. The most common problems were caused by different tests and notebooks taking different approaches to do the same thing which would cause generative code to swap between approaches between code generation.
  
- Generally speaking generative AI is not capable of producing Plugins entirely independent. However, it was very close to being able to do so and would certainly be able to greatly aid development if used as a tool by a developer.
- The quality and effectiveness of generative AI when developing the primAITE Plugins vary majorly depending on the context, prompt and the general documentation ingested during generation.
- It's actually decent at debugging if given enough relevant information however would miss simple problems often.


If the following were to be implemented then generative AI may be capable of producing usable Plugins entirely (or very close to) independently:

-  Improve the PrimAITE source code to ensure that the notebooks and docs were more explicit and consistent. 
-  Additional examples of PrimAITE Plugins and correct patterns to use.
-  Well defined and structured context and system prompts that prevent common mistakes and hallucinations.
-  Guided prompt structure for development on Plugins which prevent generative AI from over-engineering and 'wandering' off.








