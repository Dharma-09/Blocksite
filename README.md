# Website Blocker Python


Intro 
------------

Hi Guys 👋 

This repository consists the code of a simple website blocker project implemented in Python. It can be used to block certain websites during work time to reduce distraction thus improving productivity.


The magic 
--------------

The magic of this project lies on modifying the host file within your 
computer that manages how you access the web.

Getting started 
---------------------

Well to get started with this project just clone the repository 
and edit the host file location depending on the OS your using.

```bash
    $-> git clone https://github.com/Kalebu/Website-blocker-python
    $-> cd Website-blocker-python
    $ Website-blocker-python ->
```

Adding sites to block + Editing host files 
------------------------------------------------

Now open the *app.py* and the goto line 4 with variable *site_to_block*
and you can add the sites you would like to block during work time

<img src="site_to_block.png" alt="drawing" width="500"/>

Also when you go to the line no 12 and edit default host depending on 
Operating System you're using 

<img src="host_file_location.png" alt="drawing" width="500"/>

One more thing 
-------------------

You would need to set up the starting working + ending working hours where you would like to be restricted from accessing those websites
To do this go to line last line of our code and edit the hours where by.

<img src="time_to_block.png" alt="drawing" width="500"/>


