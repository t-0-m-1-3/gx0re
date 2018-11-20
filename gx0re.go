package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	pefile "github.com/awsaba/pefile-go"
)

func main() {

	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Println("    GGGGGGGGGGGGG                                          000000000     RRRRRRRRRRRRRRRRR                    EEEEEEEEEEEEEEEEEEEEEE")
	fmt.Println(" GGG::::::::::::G                                        00:::::::::00   R::::::::::::::::R                   E::::::::::::::::::::E")
	fmt.Println(" GG:::::::::::::::G                                      00:::::::::::::00 R::::::RRRRRR:::::R                  E::::::::::::::::::::E")
	fmt.Println(" G:::::GGGGGGGG::::G                                     0:::::::000:::::::0RR:::::R     R:::::R                 EE::::::EEEEEEEEE::::E")
	fmt.Println("G:::::G       GGGGGG                 xxxxxxx      xxxxxxx0::::::0   0::::::0  R::::R     R:::::R                   E:::::E       EEEEEE")
	fmt.Println("G:::::G                                x:::::x    x:::::x 0:::::0     0:::::0  R::::R     R:::::R                   E:::::E")
	fmt.Println("G:::::G                                 x:::::x  x:::::x  0:::::0     0:::::0  R::::RRRRRR:::::R                    E::::::EEEEEEEEEE")
	fmt.Println("G:::::G    GGGGGGGGGG ---------------    x:::::xx:::::x   0:::::0 000 0:::::0  R:::::::::::::RR   ---------------   E:::::::::::::::E")
	fmt.Println("G:::::G    G::::::::G -:::::::::::::-     x::::::::::x    0:::::0 000 0:::::0  R::::RRRRRR:::::R  -:::::::::::::-   E:::::::::::::::E")
	fmt.Println("G:::::G    GGGGG::::G ---------------      x::::::::x     0:::::0     0:::::0  R::::R     R:::::R ---------------   E::::::EEEEEEEEEE")
	fmt.Println("G:::::G        G::::G                      x::::::::x     0:::::0     0:::::0  R::::R     R:::::R                   E:::::E")
	fmt.Println("G:::::G       G::::G                     x::::::::::x    0::::::0   0::::::0  R::::R     R:::::R                   E:::::E       EEEEEE")
	fmt.Println("G:::::GGGGGGGG::::G                    x:::::xx:::::x   0:::::::000:::::::0RR:::::R     R:::::R                 EE::::::EEEEEEEE:::::E")
	fmt.Println("GG:::::::::::::::G                   x:::::x  x:::::x   00:::::::::::::00 R::::::R     R:::::R                 E::::::::::::::::::::E")
	fmt.Println("GGG::::::GGG:::G                  x:::::x    x:::::x    00:::::::::00   R::::::R     R:::::R                 E::::::::::::::::::::E")
	fmt.Println("GGGGGG   GGGG                 xxxxxxx      xxxxxxx     000000000     RRRRRRRR     RRRRRRR                 EEEEEEEEEEEEEEEEEEEEEE")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Print(".......................................................................................................................................\n")
	fmt.Println("       ,_---~~~~~----._         ")
	fmt.Println("_,,_,*^____      _____``*g*\\*, ")
	fmt.Println(" \\ __\\ \\'     ^.  \\      \\ ^@q   f ")
	fmt.Println("[  @f | @))    |  | @))   l  0 _\\  ")
	fmt.Println(" \\`\\   \\~____\\ __\\____\\   \\   ")
	fmt.Println("|           _l__l_           I   ")
	fmt.Println("}          [______]           I  ")
	fmt.Println("]            | | |            |  ")
	fmt.Println("]             ~ ~             |  ")
	fmt.Println("|                             | ")
	fmt.Println("| 							 |")
	fmt.Print(".............................................\n")
	fmt.Print("...........................................................\n")
	fmt.Print("...........................................................\n")
	fmt.Print("...a frame work for reverse engineering malware samples....\n")
	fmt.Print("...........................................................\n")
	fmt.Print("...........................................................\n")

	fmt.Println("\tChoose an Option to perform the type of analysis you need:\n")
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("[+] using the testing malware IRCBot.exe\n\n")
		pe, err := pefile.NewPEFile("malware_data_science/ch1/ircbot.exe")
		fmt.Println("[+] The File in question is: \n" + "[+] \t" + pe.Filename)

		for _, e := range pe.Errors {
			fmt.Println("[+] Parser warning: \n\t", e)
		}
		fmt.Println("[+] " + pe.Filename + " has been loaded successfully ")

		//Strings code start

		fmt.Println("[+] Running strings command to look for generic string indicators\n\n")
		// cmd := exec.Command("strings", "--help", "|", "grep", "help")
		// cmd := exec.Command("strings", pe.Filename, "|", "grep", "DOWNLOAD")
		// cmd := exec.Command("strings", "malware_data_science/ch1/ircbot.exe", "|", "grep", "DOWNLOAD")
		cmd := exec.Command("strings", "malware_data_science/ch1/ircbot.exe")
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("[-] I made a mistake ")
			log.Fatal(err)
		}
		fmt.Printf("%s\n", stdoutStderr)

		// strings code end?

		// Print out the Headers of The File in question
		fmt.Println(pe.DosHeader.String())
		fmt.Println(pe.DosHeader.Size)
		fmt.Println(pe.NTHeader.String())
		fmt.Println(pe.COFFFileHeader.String())
		fmt.Println(pe.OptionalHeader)

		// Print out the Sections inside the file in question
		for _, s := range pe.Sections {
			fmt.Println(s.String())
		}

		// Print ouf the ImportDescriptors

		// for _, val := range pe.ImportDescriptors {
		// fmt.Println(val)
		// for _, val2 := range val.Imports {
		// 	fmt.Println(val2)
		// }
		// }

		fmt.Println("\nDirectory_Entry_IMPORT\n")
		for _, entry := range pe.ImportDescriptors {
			fmt.Println(string(entry.Dll))
			for _, imp := range entry.Imports {
				var funcname string
				if len(imp.Name) == 0 {
					funcname = fmt.Sprintf("ordinal+%d", imp.Ordinal)
				} else {
					funcname = string(imp.Name)
				}
				fmt.Println("\t", funcname)
			}
		}

		if pe.ExportDirectory != nil {
			fmt.Println("\nDirectory_Entry_IMPORT\n")
			fmt.Println(pe.ExportDirectory)
			for _, entry := range pe.ExportDirectory.Exports {
				fmt.Printf("%d: %s:0x%x, forward: %s\n", entry.Ordinal, string(entry.Name), entry.Address, entry.Forwarder)
			}
		}
		//The code Below will be for handling the errors after testing
		// fmt.Println("Please enter a piece of software to analyze \n")
		// os.Exit(-1)
		if err != nil {
			fmt.Println(" There was a problem with the file, revert to the python script")
			fmt.Println(err)
			fmt.Println("fuck my life")
			os.Exit(2)
		}
	}
	// pe, err := pefile.NewPEFile(args[0])
	// fmt.Println("The File in question is: \n" + pe.Filename)

}
