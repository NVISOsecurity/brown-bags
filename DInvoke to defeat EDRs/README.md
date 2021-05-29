# This repository is accompanying the brown bag session of Jean-Francois Maes about defeating EDRs using Dynamic Invocation
This code is combining work from:
* EthicalChaos
* TheWover
* jfmaes


In this repository are:
* A demo loader that will just inject a messagebox using kernel32 WIN API calls (P/Invoke)
* A demo EDR, powered by the SylantStrike project of EthicalChaos
* A demo malware protector that will tamper with the attributelist of the loader to parent ID spoof and set MS STORE ONLY mitigation policy
* A demo DInvoke loader that can manualmap or use syscalls powered by the Dinvoke project of TheWover

Should you reuse any of this code for any reason, please credit the respectful people that have put in the time  and efford to provide you with these awesome projects.
