defmodule HSMServer do
  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    children = [
      # Define workers and child supervisors to be supervised
      supervisor(Task.Supervisor, [[name: HSMServer.TaskSupervisor]]),
      worker(Task, [HSMServer, :accept, [4040]])
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: HSMServer.Supervisor]
    Supervisor.start_link(children, opts)
  end

  def accept(port) do
    # The options below mean:
    #
    # 1.  `:binary` -  receives data as binaries (instead of lists)
    # 2.  `packet: raw` -  receives data as bytes and doesnt use any message delimiter
    # 3.  `active: false` -  block on `gen_tcp.recv/2`  until data is available
    #
    {:ok, socket} = :gen_tcp.listen(port, [:binary, packet: :raw, active: false])
    IO.puts "Accepting connections on port #{port}"
    loop_acceptor(socket)
  end

  defp loop_acceptor(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    Task.Supervisor.start_child(HSMServer.TaskSupervisor, fn -> serve(client) end)
    loop_acceptor(socket)
  end

  defp serve(socket) do
    import Pipe

    response =
      pipe_matching x, {:ok, x},
        read_line(socket)
        |> HSMServer.Command.parse
        |> HSMServer.Command.run

    write_line(socket, response)
    serve(socket)
  end

  @message_length 6

  defp read_line(socket) do
    # The HSM doesnt use new line to identify messages
    # So, we need to read the first @message_length bytes in order to know the size of the message
    {:ok,message_length_header} = :gen_tcp.recv(socket, @message_length)
    # Convert the bytes to a number. TODO we need to catch the exception if this fails, in order to report an error code
    {message_size, _} = Integer.parse(message_length_header)
    # Reads the rest of the message
    :gen_tcp.recv(socket, message_size)
  end

  defp write_line(socket, msg) do
    :gen_tcp.send(socket, format_msg(msg))
  end

  defp format_msg({:ok, text}) do
    # We want to simulate that the service sometimes is unavailable and responds an error code
    if :random.uniform < 0.5 do
      text
    else
      text   # Comment this line and uncomment the line below!
      # {:ok, "000015CCE110300000002"} # SERVICE UNAVAILABLE
    end
  end

  defp format_msg({:error, :unknown_command}), do: "000015CCE11030000E000" # WRONG COMMAND ERROR
  defp format_msg({:error, :invalid_message}), do: "000015CCE110300000001" # "MESSAGE FORMAT ERROR"
  defp format_msg({:error, _}), do: "000015CCE11030001C800" # EXCEPTION ERROR
end
