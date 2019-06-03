# $Id$
# $Revision$

#This next require_relative is so sniper can interact with variables that nessus.rb uses.
require_relative 'nessus'

module Msf
  class Plugin::Sniper < Msf::Plugin

	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			#This looks like a duplicate - test if it can be removed or the one further below.
			"Sniper"
		end

		def commands
                                {
			"sniper_help" => "Get help on all commands.",         
            		"sniper_scan_status" => "Check the status of running scans on your Nessus Server.",
			"sniper_report_list" => "Testing report list",
			"sniper_test" => "A sniper test command added by sniper plugin"
			}
		end

		def cmd_sniper_scan_status(*args)
			#Here call nessus_scan_status
		end
			
		def cmd_sniper_report_list(*args)
			#Here call nessus_report_list
		end
			
		def cmd_sniper_test(*args)
			print_line("You passed: #{args.join(' ')}")
		end

		def cmd_sniper_help(*args)
                                tbl = Rex::Ui::Text::Table.new(
                                        'Columns' => [
                                                'Command',
                                                'Help Text'
                                        ]
                                )
                                tbl << [ "Sniper Commands", "" ]
                                tbl << [ "-----------------", "-----------------"]
                                tbl << [ "sniper_help", "Listing of available Sniper commands" ]
                                tbl << [ "sniper_scan_status", "List the number of active nessus scans" ]
				tbl << [ "sniper_report_list", "List the nessus reports in a list" ]
				tbl << [ "sniper_test", "A sniper test command added by sniper plugin" ]
                                print_status ""
                                print_line tbl.to_s
                                print_status ""
		end
   	end

	def initialize(framework, opts)
                super
                add_console_dispatcher(ConsoleCommandDispatcher)
                print_status("Sniper plugin loaded.")
	end

	def cleanup
                remove_console_dispatcher('Sniper')
	end

	def desc
		"Sniper Bridge for Nessus/Metasploit #{@nbver}"
	end

	def name
      "sniper"
	end
	protected
  end
end

