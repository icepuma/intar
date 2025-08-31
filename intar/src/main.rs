use clap::{Parser, Subcommand};
use intar_scenario::{list_embedded_scenarios, read_embedded_scenario};

#[derive(Parser)]
#[command(name = "intar")]
#[command(about = "A CLI tool for managing intar scenarios")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scenario management commands
    Scenario {
        #[command(subcommand)]
        action: ScenarioCommands,
    },
}

#[derive(Subcommand)]
enum ScenarioCommands {
    /// List all available scenarios
    List,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scenario { action } => match action {
            ScenarioCommands::List => {
                let scenarios = list_embedded_scenarios();

                if scenarios.is_empty() {
                    println!("No scenarios found.");
                    return Ok(());
                }

                println!("Available scenarios:");
                for scenario_file in &scenarios {
                    match read_embedded_scenario(scenario_file) {
                        Ok(scenario) => {
                            println!("Name: {} - File: {}", scenario.name, scenario_file);
                            if !scenario.description.is_empty() {
                                println!("Description: {}", scenario.description);
                            }
                        }
                        Err(e) => {
                            println!("{} - (error parsing: {})", scenario_file, e);
                        }
                    }
                }
            }
        },
    }

    Ok(())
}
