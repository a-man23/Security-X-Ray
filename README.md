# Security-X-Ray
Security X‑Ray: Visualizing Third-Party Web Code for Security and Privacy. For ECE507.

Current Limitations: 
Anything the page loads dynamically after JS runs is invisible don't want to run untrusted code and keeps crawler lightweight

Originally crawler was marking CDNs as third party scripts even though they were operated by the same owner because they were under differnet domain ie. nytimes.com and nyt.com
Im just adding them to a known list as i go (update aliases.json)
