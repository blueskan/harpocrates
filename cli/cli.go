package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/blueskan/harpocrates/service"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
)

type Cli struct {
	passwordService service.PasswordService
}

func NewCli() *Cli {
	return &Cli{}
}

func (c *Cli) Banner() {
	fmt.Println(`
	_     ____  ____  ____  ____  ____  ____  ____  _____  _____ ____ 
	/ \ /|/  _ \/  __\/  __\/  _ \/   _\/  __\/  _ \/__ __\/  __// ___\
	| |_||| / \||  \/||  \/|| / \||  /  |  \/|| / \|  / \  |  \  |    \
	| | ||| |-|||    /|  __/| \_/||  \__|    /| |-||  | |  |  /_ \___ |
	\_/ \|\_/ \|\_/\_\\_/   \____/\____/\_/\_\\_/ \|  \_/  \____\\____/
																			
	`)
}

func (c *Cli) WelcomeMessage() {
	fmt.Println("Welcome to Haprocrates, we need setup some of your configurations..\n\n	")
}

func (c *Cli) Repl() {
	prompt := promptui.Select{
		Label: "Select Operation",
		Items: []string{"Store Password", "Delete Password", "Get Password", "List Passwords", "Export All Passwords to CSV", "Exit"},
	}

	for {
		_, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch result {
		case "Store Password":
			validateName := func(input string) error {
				if len(input) <= 0 {
					return errors.New("You should enter name")
				}

				return nil
			}

			prompt := promptui.Prompt{
				Label:    "Name",
				Validate: validateName,
			}

			resultName, _ := prompt.Run()

			// Difference

			validateUrl := func(input string) error {
				return nil
			}

			prompt = promptui.Prompt{
				Label:    "Url",
				Validate: validateUrl,
			}

			resultUrl, _ := prompt.Run()

			// Difference

			validatePassword := func(input string) error {
				if len(input) <= 0 {
					return errors.New("You should enter password")
				}

				return nil
			}

			prompt = promptui.Prompt{
				Label:    "Password",
				Validate: validatePassword,
				Mask:     '*',
			}

			resultPassword, _ := prompt.Run()

			c.storePassword(&service.PasswordRepresentation{
				Name:     resultName,
				Url:      resultUrl,
				Password: resultPassword,
			})

			fmt.Println("Password successfully saved..")
		case "Get Password":
			validateName := func(input string) error {
				return nil
			}

			prompt := promptui.Prompt{
				Label:    "Name",
				Validate: validateName,
			}

			resultName, _ := prompt.Run()

			passwordInformation, err := c.getPassword(resultName)

			if err != nil {
				fmt.Println(err.Error())
				break
			}

			data := [][]string{
				[]string{passwordInformation.Name, passwordInformation.Url, passwordInformation.Password},
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Url", "Password"})

			for _, v := range data {
				table.Append(v)
			}

			table.Render()
		case "Delete Password":
			validateName := func(input string) error {
				return nil
			}

			prompt := promptui.Prompt{
				Label:    "Name",
				Validate: validateName,
			}

			resultName, _ := prompt.Run()

			err := c.deletePassword(resultName)

			if err != nil {
				fmt.Printf(err.Error())
				break
			}

			fmt.Printf("Password named as `%s` deleted successfully", resultName)
		case "List Passwords":
			passwordList := c.listPasswords()

			if len(passwordList) <= 0 {
				fmt.Println("There are no stored passwords")
				break
			}

			stringArrList := make([][]string, 0)
			for _, val := range passwordList {
				row := []string{val.Name, val.Url}

				stringArrList = append(stringArrList, row)
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Url"})

			for _, v := range stringArrList {
				table.Append(v)
			}

			table.Render()
		case "Export All Passwords to CSV":
			validateName := func(input string) error {
				return nil
			}

			prompt := promptui.Prompt{
				Label:    "Please enter pathname with filename of csv",
				Validate: validateName,
			}

			filename, _ := prompt.Run()

			c.exportToCsv(filename)

			fmt.Printf("All passwords saved to `%s`\n", filename)
		case "Exit":
			fmt.Println("Goodbye :)")
			os.Exit(0)
		}
	}
}

func (c *Cli) storePassword(representation *service.PasswordRepresentation) {
	c.passwordService.StorePassword(*representation)
}

func (c *Cli) listPasswords() []*service.PasswordRepresentation {
	return c.passwordService.ListPasswords()
}

func (c *Cli) getPassword(name string) (*service.PasswordRepresentation, error) {
	return c.passwordService.GetPassword(name)
}

func (c *Cli) deletePassword(name string) error {
	return c.passwordService.DeletePassword(name)
}

func (c *Cli) exportToCsv(filename string) {
	c.passwordService.ExportToCsv(filename)
}

func (c *Cli) AskEncryptionBits() string {
	prompt := promptui.Select{
		Label: "Encryption Bit Count",
		Items: []string{"2048", "4096", "8192"},
	}

	_, result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}

	return result
}

func (c *Cli) AskMasterPassword() string {
	validate := func(input string) error {
		if len(input) < 6 {
			return errors.New("Password must have more than 6 characters")
		}

		return nil
	}

	prompt := promptui.Prompt{
		Label:    "You need to set master password",
		Validate: validate,
		Mask:     '*',
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}

	return result
}

func (c *Cli) AskServerPort() string {
	validate := func(input string) error {
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "You need to set server port",
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}

	return result
}

func (c *Cli) AskServerAddr() string {
	validate := func(input string) error {
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "You need to set server address",
		Validate: validate,
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}

	return result
}

func (c *Cli) SetPasswordService(passwordService service.PasswordService) {
	c.passwordService = passwordService
}
