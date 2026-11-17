defmodule Sniper.MixProject do
  use Mix.Project

  def project do
    [
      app: :sniper,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Sniper, []}
    ]
  end

  defp deps do
    [
      {:gun, "~> 2.1"},
      {:finch, "~> 0.19"},
      {:castore, "~> 1.0"},
      {:jason, "~> 1.4"},
      {:file_system, "~> 1.0"}
    ]
  end
end
