defmodule HSMServer.Command do
@doc """
  Command Message structure:

  Type   Length     Comment
   D      6      Message length    For us will be 001347
   A      var    Header (*)        In our case var = 3. TODO: Check this value in the HSM configuration
   H      4      Command Identifier
   --     var    Command Data

   (*)The messages format allows a header length parameterized by the Entity.
   In HSM response arrive this header unchanged, so that the application that
   made the request verify that the message actually returned is that one which expects.
"""
  @header_code  "CCE"     # I production we are usign this header code
  @asym_code    "1103"    # In production we are just usign Asymetric Signature feature

  @doc ~S"""
  Parses the given `line` into a command.

  ## Examples

      iex> HSMServer.Command.parse "CCE1103PRIVATE_KEY100101000040AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      {:ok, {"1103", "PRIVATE_KEY", "10", "01", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}}

      iex> HSMServer.Command.parse "INVALID001347CCE1103PRIVATE_KEY100101000040"
      {:error, :invalid_message}

      iex> HSMServer.Command.parse "111247CCE1103PRIVATE_KEY100101000040"
      {:error, :invalid_message}

      iex> HSMServer.Command.parse "CCE1104PRIVATE_KEY100101000040AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      {:error, :unknown_command}
  """
  def parse(@header_code <> command) do
     parse_command(command, @header_code)
  end

  def parse(_command) do
    {:error, :invalid_message}
  end

  @hash_length 40  # This is the size of the hash we are sending in production
  @private_key 11  # Change 11 to 1288 for production
  def parse_command(command, header_code) do
    case command do
      <<command_id    :: binary-size(4),
        private_key   :: binary-size(@private_key),
        hash_mecanism :: binary-size(2),
        sign_mecanism :: binary-size(2),
        padeo         :: binary-size(2),
        hash_length   :: binary-size(6),
        hash_bits     :: binary-size(@hash_length)>>
        when <<command_id :: binary-size(4)>> == @asym_code ->
          {:ok, {<<command_id    :: binary-size(4)>>,
                 <<private_key   :: binary-size(@private_key)>>,
                 <<hash_mecanism :: binary-size(2)>>,
                 <<sign_mecanism :: binary-size(2)>>,
                 <<padeo         :: binary-size(2)>>,
                 <<hash_length   :: binary-size(6)>>,
                 <<hash_bits     :: binary-size(@hash_length)>>,
                 header_code}}
        _ ->
          {:error, :unknown_command }
    end
  end

  @sha1  "10"
  @rsa   "01"
  @pkcs1 "01"
  @hash_length "000040"
  @doc """
    General Response Message structure:

   Type   Length      Comment
    D       6      Message length       This is removed by the HSMServer.read_line function
    A      var     Header
    H       4      Command Identifier
    H       8      Command State
    --     var     Response Data(2*)

    (2*)This field will be present only if the command has been successfully resolved,
    that is, if the state of the command is ‘00000000’.

    Command Response message:

    Dato  Tipo  Longitud        Comentario
    IC     H      4       Identificador de comando.
    RV     H      8       Valor de retorno.
    LFIR   N      6       Longitud del siguiente campo.
    FIR    H      var     Firma
  """

  @doc ~S"""
  Parses the given `line` into a command.

  ## Examples

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "10", "01", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:ok, "000277CCE110300000000000256AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}

      iex> HSMServer.Command.run {"1101", "PRIVATE_KEY", "10", "01", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:error, "000015CCE110100018400"}

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "14", "01", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:error, "000015CCE110300018400"}

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "10", "11", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:error, "000015CCE110300018400"}

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "10", "01", "10", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:error, "000015CCE110300018400"}

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "10", "01", "01", "000050", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCE"}
      {:error, "000015CCE110300018400"}

      iex> HSMServer.Command.run {"1103", "PRIVATE_KEY", "10", "01", "01", "000040", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "DCE"}
      {:error, "000015DCE110300018400"}

  """
  def run({@asym_code, _private_key, @sha1, @rsa, @pkcs1, @hash_length, _hash, @header_code}) do
    # message's bytes = 283 bytes. If everything is ok, this is all the data the client needs to read
    message_length    = "000277"   # We always return a message with this length for the 1103 command. 283 - 6 bytes
    command_state     = "00000000" # It means that everything was ok
    signature_length  = "000256"   # It is always 256 length for a RSA Asymetric signature
    signature = for _ <- 1..256, into: "", do: "A"
    # message_length = 6, header_code = 3, command_id = 4, command_state = 8, signature_length = 6  ==  27 bytes
    # signature = 283 - 27 = 256 bytes
    {:ok, message_length <> @header_code <> @asym_code <> command_state <> signature_length <> signature}
  end

  def run({command_id, _private_key, _hash_mecanism, _sign_mecanism, _padeo, _hash_length, _hash, header_code}) do
    command_state  = "00018400" # NOT ALLOWED IN PRODUCTIONSTATE
    message_length = "000015"   # We always return a message with this length for any error.
    {:error, message_length <> header_code <> command_id <> command_state}
  end

end