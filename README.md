<h1 align="center">MalTDec3: Malicious Traffic Detection in a Network using 3 Layer Inspection</h1>
<p align="center">
  <a href="#description">Description</a> |
  <a href="#paper">Research Paper</a>
</p>

# Description
Source Code of MalTDec3 research project.

# Research Paper
Internet has seen a great advancement and increased users in recent years. At the time of writing this paper there are five billion internet users worldwide. Internet is nothing but a global network of inter-connected devices, and one of main challenge that is faced by any network is of malicious activity carried out by adversaries. To tackle this problem there have been many studies carried out by researchers, some of the well known solutions are Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) based on Machine Learning and Deep Learning Techniques. Here in our study we propose a 3 Layer Inspection method to analyse the packets thoroughly and determine if a network traffic is malicious or not. In our proposed method, Layer 1 is used to compare the Destination Address of a packet with publicly-known malicious IP addresses, Layer 2 extracts keywords from the data of different protocols and compares it against a curated list of potential keywords. These two layers can detect already known malicious activities, but attackers are now inventing new techniques so in Layer 3 we used 1 Class SVM on top of different dimensionality reduction architecture to detect any abnormality in a network that may be missed by Layer 1 and Layer 2. For training Layer 3 with different Machine Learning Algorithms, we generated a new data-set with 10 features of real time traffic. Firstly dimensionality reduction is performed using PCA, t-SNE and AutoEncoder then Layer 3 is trained with 1 Class SVM algorithm

<a href="https://ieeexplore.ieee.org/document/9913598">CCICT 2022, India</a>
