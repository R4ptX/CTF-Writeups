__MetaCTF Febuary 2025 - "Till Delete Do Us Part" Writeup__
---

__Challenge Description__ 
---
I was messing with trying to dual boot, and while trying to fix partitions, I accidentally deleted the one on my wedding flash drive I carelessly had plugged in! Please help me recover it! 
---
In this challenge, we are tasked to download a corrupted iso partition file and try and recover the data that is lost. 

__Step 1: Download a notable data recovery software to try and repair the corrupted file.__
For this challenge in particular, DMDE (Disk Editor and Data Recovery Software) was used. 


__Step 2: Open the usb file on DMDE.__
If you do the recovery correctly, there should be a new img file that appears that's called usb.1. You click this file aswell and it should open up to this structure: 

![usb_structure)](usb_file_structure.png)
