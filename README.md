# RZA Website Source
Source code for the T-Level Digital Production, Design and Development Exam 2024.

This is where you can view the source code for the project. This was developed over a 30-hour period split across 4 weeks. 
View the live site here - https://smallerbenus.pythonanywhere.com/


During this 4 week period, we had to have our exams rescheduled at least 4 times, with them being cancelled entirely on multiple occasions. 
We had 3 student's work permanently lost - or at least partially lost - with mine luckily being recovered.
All of these factors contributed to the lack of a finished product.

When filling out the form, if you don't know what to write about, say something about these:

# Missing Features
These are features that were intended to be implemented but were not due to time constraints.

- The user cannot reset their password
- The user cannot delete their account
- Loyalty Points have no purpose

# Current known issues
These are issues with the current build that were not fixed before going into testing.

- Loyalty Points always give 10 points instead of rewarding based on booking price.
- Some pages on smaller screens do not scale correctly ("Educational Visits" page)
- Some buttons on smaller screens do not align correctly ("Book Tickets" button)
- Some content on larger/higher resolution screens does not scale to fit (Backgrounds, images)

# Potential Security Risks
These are issues that should be addressed before deploying into a real-world scenario. 

- Encryption keys are declared directly in the Python code
- Encryption and decryption functions are stored in the main backend Python file
- Session cookies could potentially be stolen and used to bypass the login to gain access to someone's account
