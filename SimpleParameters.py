from optparse import OptionParser
import json, os

'''

Mandatory -
A short name is mandatory to get started
Additionally, a long name, type, default value and help text can be specified
in the options configuration file

Any option without a type is taken as a boolean
Anything with a type must have additional parameter following it

'''
    
class SimpleParameters():

    OPTIONS_FILE = 'data/SimpleParameters.txt'
    VERSION = "Your version goes here. Specify it in the options file"
    DESCRIPTION= "A small description of the application goes here. Specify it in the options file"    

    def __init__(self, options_file =OPTIONS_FILE,
                          version = VERSION, 
                          description = DESCRIPTION):        

        #Open the options file and load all the options into json
        if os.path.isfile(options_file):
            with open(options_file) as infile:
                self.all_options = json.load(infile)

                if(self.all_options.get('version')):
                   version = self.all_options.get('version')
                if(self.all_options.get('description')):
                   description = self.all_options.get('description')
                self.all_options = self.all_options.get("parameters")
                
                #Create an option parser
                self.parser = OptionParser(version = version, description = description)                        
                #Parse through each of the options one by one
                for key, option in self.all_options.items():
                    self.parse_each_option(option)
        else:
            raise Exception("Options file {} not found.".format(options_file))

    def parse_each_option(self, option):
        long = option.get('long')
        default = option.get('default')
        help = option.get('help')

    #If the type of the variable is not specified, it is a flag
        if not(option.get('type')):
            #Store the variable as true or false
            action = "store_true"
            if default == 'true':
                default=True
            else:
                default=False

            #Consider the cases of various pptional parameters not being specified   
            if long and default and help:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                    ,default = default, action = action
                , help=option['help'])        
            elif default and help    :
                self.parser.add_option(option['short']
                      ,dest=self.get_var_name(option)
                    ,default = default, action = action
                , help=option['help'])
            elif long and help:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                    , action = action
                , help=option['help'])                    
            elif long and default:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                    ,default = default, action = action)
            elif default:
                self.parser.add_option(option['short']
                      ,dest=self.get_var_name(option)
                    ,default = default, action = action)
            elif long:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option), action = action)
            else:
                self.parser.add_option(option['short']
                      ,dest=self.get_var_name(option)
                        , action = action)
        else:
            '''
    Likely types include string, int, float which should be stored in the
    destination variable derived from long/short name

    Consider the various optional attributes being specified or not
            '''
            action = 'store'
            if long and default and help:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                    , type=option.get('type')            
                    ,default = default, action = action
                , help=option['help'])        
            elif default and help    :
                self.parser.add_option(option['short']
                      ,dest=self.get_var_name(option)
                    ,default = default, action = action
                , type=option.get('type')                 
                , help=option['help'])
            elif long and help:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                    , action = action
                , type=option.get('type')                                               
                , help=option['help'])                    
            elif long and default:
                self.parser.add_option(option['short'], long
                      ,dest=self.get_var_name(option)
                , type=option.get('type')                                               
                    ,default = default, action = action)
            elif default:
                self.parser.add_option(option['short']
                      ,dest=self.get_var_name(option)
                , type=option.get('type')                                               
                    ,default = default, action = action)
            elif long:
                self.parser.add_option(option['short'], long
                , type=option.get('type')
                      ,dest=self.get_var_name(option), action = action)
            else:
                self.parser.add_option(option['short']
                , type=option.get('type')                                                            
                      ,dest=self.get_var_name(option)
                        , action = action)
        return

    def get_var_name(self, options):
    #Create the name of the variable from the name of the option
            if options.get("long"):
                str(options.get("long")).strip("--").replace("-","_")
            elif options.get("short"):
                str(options.get("short")).strip("-")
            return

    def resolve_parameters(self, params):
            return self.parser.parse_args(params)
                           

    #---------------------------------------------------------------


#Just run a basic test
if __name__=="__main__":
#Execute the parse after all the options have been added
        import sys
        try:
            parser = SimpleParameters()
            (options, args) =\
                parser.resolve_parameters(sys.argv)            

            if(options.file):
                parser = SimpleParameters()
                (options, args) =\
                    parser.resolve_parameters(args)
                parser.parser.print_help()
        except Exception as ex:
            print(ex)
