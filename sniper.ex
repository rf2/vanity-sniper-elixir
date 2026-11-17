defmodule Sniper do
  use Application
  @compile {:inline, [fire: 1, scan_event: 1, prebuild: 3, request_and_log: 2]}

  def start(_type, _args) do
    Task.start(fn -> run() end)
  end

  def run do
    Process.flag(:priority, :max)
    :persistent_term.put(:vanity_list, [])
    config = load_config()
    init_pools(config)

    tokens = 
      if File.exists?("list.txt") do
        "list.txt"
        |> File.read!()
        |> String.split(["\r\n", "\n"], trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.filter(&(&1 != ""))
      else
        [config.token]
      end

    tokens = if tokens == [], do: [config.token], else: tokens
    total = length(tokens)

    spawn_link(fn -> watch_mfa(config) end)

    Enum.with_index(tokens) |> Enum.each(fn {tok, idx} ->
      spawn_link(fn -> connect(tok, idx, total, config) end)
    end)

    keep_alive()
  end

  defp keep_alive do
    receive do
      _ -> keep_alive()
    end
  end

  defp load_config do
    "config.json" |> File.read!() |> Jason.decode!(keys: :atoms)
  end

  defp read_mfa do
    case File.read("mfa.txt") do
      {:ok, bin} ->
        t = String.trim(bin)
        if byte_size(t) > 0, do: t, else: nil

      _ ->
        nil
    end
  end

  defp watch_mfa(config) do
    Process.flag(:priority, :max)
    current = read_mfa()
    rebuild_all(config, current)

    case FileSystem.start_link(dirs: ["."]) do
      {:ok, watcher_pid} ->
        FileSystem.subscribe(watcher_pid)
        mfa_fs_loop(config, current)

      _ ->
        mfa_fs_loop(config, current)
    end
  end

  defp mfa_fs_loop(config, old_mfa) do
    receive do
      {:file_event, _, {path, _}} ->
        if String.ends_with?(path, "mfa.txt") do
          current = read_mfa()
          if current && current != old_mfa do
            rebuild_all(config, current)
            IO.puts("mfa rebuild")
            mfa_fs_loop(config, current)
          else
            mfa_fs_loop(config, old_mfa)
          end
        else
          mfa_fs_loop(config, old_mfa)
        end

      _ ->
        mfa_fs_loop(config, old_mfa)
    after
      3000 ->
        current = read_mfa()
        if current && current != old_mfa do
          rebuild_all(config, current)
          IO.puts("mfa rebuild")
          mfa_fs_loop(config, current)
        else
          mfa_fs_loop(config, old_mfa)
        end
    end
  end

  defp rebuild_all(config, mfa) do
    list = :persistent_term.get(:vanity_list, [])
    Enum.each(list, fn {_gid, code} ->
      prebuild(code, config, mfa)
    end)
  end

  def prebuild(code, config, mfa_token) do
    body = "{\"code\":\"#{code}\"}"
    len = byte_size(body) |> Integer.to_string()
    url = "https://canary.discord.com/api/v9/guilds/#{config.guild_id}/vanity-url"

    h1_headers = [
      {"authorization", config.token},
      {"content-type", "application/json"},
      {"accept", "*/*"},
      {"accept-encoding", "identity"},
      {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
      {"x-super-properties", "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50YnVpbGRfbnVtYmVyIjozNTU2MjR9"},
      {"content-length", len}
    ] ++ if mfa_token && mfa_token != "", do: [{"x-discord-mfa-authorization", mfa_token}], else: []

    h2_headers = [
      {"authorization", config.token},
      {"content-type", "application/json"},
      {"accept", "*/*"},
      {"accept-encoding", "identity"},
      {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
      {"x-super-properties", "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50YnVpbGRfbnVtYmVyIjozNTU2MjR9"}
    ] ++ if mfa_token && mfa_token != "", do: [{"x-discord-mfa-authorization", mfa_token}], else: []

    h1_req = Finch.build(:patch, url, h1_headers, body)
    h2_req = Finch.build(:patch, url, h2_headers, body)

    :persistent_term.put({:prebuilt, code}, {h1_req, h2_req})
  end

  defp init_pools(config) do
    req_count_tls = Map.get(config, :req_count_tls, 12)
    req_count_h2 = Map.get(config, :req_count_h2, 12)

    ca_path =
      if File.exists?("/etc/ssl/certs/ca-certificates.crt") do
        ~c"/etc/ssl/certs/ca-certificates.crt"
      else
        to_charlist(CAStore.file_path())
      end

    base_transport_opts = [
      verify: :verify_peer,
      cacertfile: ca_path,
      versions: [:"tlsv1.3"],
      ciphers: [%{cipher: :aes_128_gcm, key_exchange: :any, mac: :aead, prf: :sha256}],
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      server_name_indication: to_charlist("canary.discord.com"),
      nodelay: true,
      keepalive: true,
      reuseaddr: true,
      sndbuf: 65536,
      recbuf: 65536,
      buffer: 65536
    ]

    if req_count_tls > 0 do
      Finch.start_link(
        name: SniperFinchH1,
        pools: %{
          "https://canary.discord.com" => [
            protocols: [:http1],
            size: max(req_count_tls, 12),
            count: 4,
            conn_opts: [transport_opts: base_transport_opts ++ [alpn_advertised_protocols: ["http/1.1"]]]
          ]
        }
      )
    end

    if req_count_h2 > 0 do
      Finch.start_link(
        name: SniperFinchH2,
        pools: %{
          "https://canary.discord.com" => [
            protocols: [:http2],
            count: max(req_count_h2, 12),
            conn_opts: [transport_opts: base_transport_opts ++ [alpn_advertised_protocols: ["h2"]]]
          ]
        }
      )
    end
  end

  defp request_and_log(req, pool) do
    case Finch.request(req, pool) do
      {:ok, %{body: body}} ->
        if byte_size(body) > 0 and (String.contains?(body, "\"code\"") or String.contains?(body, "\"message\"")) do
          IO.puts("[allahrequest] #{body}")
        end

      _ ->
        :ok
    end
  end

  def fire(code) do
    case :persistent_term.get({:prebuilt, code}, nil) do
      {h1_req, h2_req} ->
        for _ <- 1..12 do
          spawn(fn -> request_and_log(h2_req, SniperFinchH2) end)
          spawn(fn -> request_and_log(h1_req, SniperFinchH1) end)
        end

      _ ->
        :ok
    end
  end

  @gw_host ~c"gateway-us-east1-b.discord.gg"
  @gw_port 443
  @gw_path "/?v=9&encoding=json"
  @ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

  def connect(token, index, total, cfg) do
    Process.flag(:priority, :max)

    tls_opts = [
      verify: :verify_none,
      server_name_indication: @gw_host,
      nodelay: true,
      keepalive: true,
      reuseaddr: true,
      sndbuf: 65536,
      recbuf: 65536,
      buffer: 65536
    ]

    case :gun.open(@gw_host, @gw_port, %{
      transport: :tls,
      tls_opts: tls_opts,
      protocols: [:http]
    }) do
      {:ok, conn} ->
        case :gun.await_up(conn, 5000) do
          {:ok, :http} ->
            ref = :gun.ws_upgrade(conn, @gw_path, [{"User-Agent", @ua}])
            loop(conn, ref, token, index, total, cfg, nil, true)

          _err ->
            :gun.close(conn)
            Process.sleep(1500)
            connect(token, index, total, cfg)
        end

      _err ->
        Process.sleep(1500)
        connect(token, index, total, cfg)
    end
  end

  defp loop(conn, ref, token, index, total, config, hb_ref, hb_acked) do
    receive do
      {:gun_upgrade, ^conn, ^ref, [<<"websocket">>], _} ->
        loop(conn, ref, token, index, total, config, hb_ref, hb_acked)

      {:gun_ws, ^conn, ^ref, {:text, json}} ->
        scan_event(json)

        case json do
          <<"{\"op\":11", _::binary>> ->
            loop(conn, ref, token, index, total, config, hb_ref, true)

          _ ->
            {new_hb_ref, new_hb_acked} =
              handle_event(Jason.decode!(json), conn, ref, token, index, total, config, hb_ref, hb_acked)

            loop(conn, ref, token, index, total, config, new_hb_ref, new_hb_acked)
        end

      :heartbeat ->
        if !hb_acked do
          reconnect(conn, hb_ref, token, index, total, config)
        else
          send_json(conn, ref, %{"op" => 1, "d" => nil})
          loop(conn, ref, token, index, total, config, hb_ref, false)
        end

      {:gun_ws, ^conn, ^ref, {:close, _code, _reason}} ->
        reconnect(conn, hb_ref, token, index, total, config)

      {:gun_down, ^conn, _, _, _} ->
        reconnect(conn, hb_ref, token, index, total, config)

      _ ->
        loop(conn, ref, token, index, total, config, hb_ref, hb_acked)
    end
  end

  defp handle_event(%{"op" => 10, "d" => %{"heartbeat_interval" => interval}}, conn, ref, token, _index, _total, _config, old_ref, _) do
    if old_ref, do: :timer.cancel(old_ref)
    {:ok, tref} = :timer.send_interval(interval, self(), :heartbeat)

    payload = %{
      "op" => 2,
      "d" => %{
        "token" => token,
        "intents" => 1,
        "properties" => %{"os" => "Windows", "browser" => "chrome", "device" => ""},
        "guild_subscriptions" => false,
        "large_threshold" => 0
      }
    }

    send_json(conn, ref, payload)
    {tref, true}
  end

  defp handle_event(%{"op" => 11}, _conn, _ref, _token, _index, _total, _config, hb_ref, _) do
    {hb_ref, true}
  end

  defp handle_event(%{"op" => op}, conn, _ref, token, index, total, config, hb_ref, _) when op in [7, 9] do
    reconnect(conn, hb_ref, token, index, total, config)
    {hb_ref, true}
  end

  defp handle_event(%{"op" => 0, "t" => event, "d" => data}, _conn, _ref, _token, index, total, config, hb_ref, hb_acked) do
    dispatch(event, data, index, total, config)
    {hb_ref, hb_acked}
  end

  defp handle_event(_, _conn, _ref, _token, _index, _total, _config, hb_ref, hb_acked), do: {hb_ref, hb_acked}

  defp send_json(conn, ref, payload) do
    :gun.ws_send(conn, ref, {:text, Jason.encode!(payload)})
  end

  defp reconnect(conn, hb_ref, token, index, total, config) do
    if hb_ref, do: :timer.cancel(hb_ref)
    if conn, do: :gun.close(conn)
    Process.sleep(1500)
    connect(token, index, total, config)
  end

  defp dispatch("READY", %{"guilds" => guilds}, index, total, cfg) do
    mfa = read_mfa()

    all_vanities = extract_vanities(guilds) |> Enum.uniq()

    vanity_codes =
      Enum.map(all_vanities, fn {gid, code} ->
        :persistent_term.put({:vanity, gid}, code)
        prebuild(code, cfg, mfa)
        code
      end)

    :persistent_term.put(:vanity_list, Enum.map(vanity_codes, &{cfg.guild_id, &1}))

    IO.puts("mfa rebuild")
    IO.puts("[+] Gateway connected! Monitor token #{index + 1}/#{total} baglandi (#{length(guilds)} sunucu)")
  end

  defp dispatch(_, _, _, _, _), do: :ok

  defp extract_vanities(node) do
    do_extract_vanities(node, nil, []) |> Enum.reverse()
  end

  defp do_extract_vanities(node, current_id, acc) when is_map(node) do
    node_id = Map.get(node, "id", current_id)

    acc =
      case {node_id, Map.get(node, "vanity_url_code")} do
        {id, code} when is_binary(id) and is_binary(code) -> [{id, code} | acc]
        _ -> acc
      end

    Enum.reduce(node, acc, fn {_key, value}, current_acc ->
      do_extract_vanities(value, node_id, current_acc)
    end)
  end

  defp do_extract_vanities(list, current_id, acc) when is_list(list) do
    Enum.reduce(list, acc, fn value, current_acc ->
      do_extract_vanities(value, current_id, current_acc)
    end)
  end

  defp do_extract_vanities(_, _current_id, acc), do: acc

  defp scan_event(raw) do
    if String.contains?(raw, ~s("t":"GUILD_UPDATE")) do
      case String.split(raw, ~s("id":"), parts: 2) do
        [_, after_id] ->
          case String.split(after_id, ~s("), parts: 2) do
            [gid, _] ->
              case String.split(raw, ~s("premium_subscription_count":), parts: 2) do
                [_, after_boost] ->
                  case Integer.parse(after_boost) do
                    {count, _} when count < 14 ->
                      if old_code = :persistent_term.get({:vanity, gid}, nil) do
                        fire(old_code)
                      end

                    _ ->
                      if String.contains?(raw, ~s("vanity_url_code":null)) do
                        if old_code = :persistent_term.get({:vanity, gid}, nil) do
                          fire(old_code)
                        end
                      else
                        case String.split(raw, ~s("vanity_url_code":"), parts: 2) do
                          [_, after_vanity] ->
                            case String.split(after_vanity, ~s("), parts: 2) do
                              [new_code, _] ->
                                if (old_code = :persistent_term.get({:vanity, gid}, nil)) && old_code != new_code do
                                  fire(old_code)
                                end

                              _ ->
                                :ok
                            end

                          _ ->
                            :ok
                        end
                      end
                  end

                _ ->
                  if String.contains?(raw, ~s("vanity_url_code":null)) do
                    if old_code = :persistent_term.get({:vanity, gid}, nil) do
                      fire(old_code)
                    end
                  else
                    case String.split(raw, ~s("vanity_url_code":"), parts: 2) do
                      [_, after_vanity] ->
                        case String.split(after_vanity, ~s("), parts: 2) do
                          [new_code, _] ->
                            if (old_code = :persistent_term.get({:vanity, gid}, nil)) && old_code != new_code do
                              fire(old_code)
                            end

                          _ ->
                            :ok
                        end

                      _ ->
                        :ok
                    end
                  end
              end

            _ ->
              :ok
          end

        _ ->
          :ok
      end
    else
      :ok
    end
  end
end
