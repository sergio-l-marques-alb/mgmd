#!/bin/sh

echo ""
echo "How-to integrate MGMD in a new project"
echo ""
echo "1. First step is to create a new output directory on which all objects will"
echo "   be generated. As a suggestion you can create new directory inside './build/'"
echo ""
echo "2. Use the './build/configure-example.sh' as a template, and create a new one"
echo "   inside the new project directory"
echo ""
echo "3. Edit the file and make sure that the path for the 'configure' file is correct!"
echo "   NOTE: the configure file is automatically generated after the next step."
echo ""
echo "4. Now you can run the 'autogen.sh' script from the main MGMD path. This script"
echo "   will generate several files that are fully independent from your project,"
echo "   including the configure file mentioned on the previous step"
echo ""
echo "5. Run the configure file that you adapted to your project (inside the directory"
echo "   that you created for that purpose)"
echo ""
echo "6. Finally you are ready to run make all, and make install! :)"
echo ""
