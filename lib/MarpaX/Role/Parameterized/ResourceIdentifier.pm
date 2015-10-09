package MarpaX::Role::Parameterized::ResourceIdentifier;
use Carp;
use strictures 2;
use Types::Standard -all;
use Marpa::R2;
use Moo::Role;
use MooX::Role::Parameterized;
use MooX::ClassAttribute;
use MooX::HandlesVia;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORTIY

# AUTHORITY

#
# URI/IRI are sharing EXACTLY the same implementation algorithm, only some names are changing.
#
# This is why they consume this parameterized role.
#
role {
  my $params = shift;

  #
  # Default naming of published attributes/methods
  #
  our @PUBLIC = qw/value
                   grammar bnf
                   scheme authority path query fragment hier_part userinfo host port relative_part ip_literal zoneid ipv4address reg_name
                   scheme_normalization protocol_normalization
                   canonical is_absolute/;
  foreach (@PUBLIC) {
    $params->{$_} //= $_;
  }

  #
  # Default naming of internal attributes/methods
  #
  our @PRIVATE = qw/_parse _normalize _remove_dot_segments
                    _marpa_concat _marpa_scheme _marpa_authority _marpa_path _marpa_query _marpa_fragment
                    _marpa_hier_part _marpa_userinfo _marpa_host _marpa_port _marpa_relative_part _marpa_ip_literal
                    _marpa_zoneid _marpa_ipv4address _marpa_reg_name/;
  foreach (@PRIVATE) {
    $params->{$_} //= $_;
  }

  #
  # Default naming of grammar rules
  #
  our @RULES = ('<pct encoded>', '<path abempty>', '<path absolute>', '<path noscheme>', '<path rootless>', '<path empty>');
  foreach (@RULES) {
    $params->{$_} //= $_;
  }

  my $value                          = $params->{value};
  my $grammar                        = $params->{grammar};
  my $BNF_section_data               = $params->{BNF_section_data};
  my $bnf                            = $params->{bnf};
  my $scheme                         = $params->{scheme};
  my $authority                      = $params->{authority};
  my $path                           = $params->{path};
  my $query                          = $params->{query};
  my $fragment                       = $params->{fragment};
  my $hier_part                      = $params->{hier_part};
  my $userinfo                       = $params->{userinfo};
  my $host                           = $params->{host};
  my $port                           = $params->{port};
  my $relative_part                  = $params->{relative_part};
  my $ip_literal                     = $params->{ip_literal};
  my $zoneid                         = $params->{zoneid};
  my $ipv4address                    = $params->{ipv4address};
  my $reg_name                       = $params->{reg_name};
  my $_exists_scheme_normalization   = '_exists_' . $params->{scheme_normalization};
  my $_get_scheme_normalization      = '_get_' . $params->{scheme_normalization};
  my $_exists_protocol_normalization = '_exists_' . $params->{protocol_normalization};
  my $_get_protocol_normalization    = '_get_' . $params->{protocol_normalization};
  my $_trigger_value                 = '_trigger_' . $params->{value};
  my $scheme_normalization           = $params->{scheme_normalization};
  my $protocol_normalization         = $params->{protocol_normalization};
  my $canonical                      = $params->{canonical};
  my $_parse                         = $params->{_parse};
  my $is_absolute                    = $params->{is_absolute};
  my $_normalize                     = $params->{_normalize};
  my $_remove_dot_segments           = $params->{_remove_dot_segments};
  my $_marpa_concat                  = $params->{_marpa_concat};
  my $_marpa_scheme                  = $params->{_marpa_scheme};
  my $_marpa_authority               = $params->{_marpa_authority};
  my $_marpa_path                    = $params->{_marpa_path};
  my $_marpa_query                   = $params->{_marpa_query};
  my $_marpa_fragment                = $params->{_marpa_fragment};
  my $_marpa_hier_part               = $params->{_marpa_hier_part};
  my $_marpa_userinfo                = $params->{_marpa_userinfo};
  my $_marpa_host                    = $params->{_marpa_host};
  my $_marpa_port                    = $params->{_marpa_port};
  my $_marpa_relative_part           = $params->{_marpa_relative_part};
  my $_marpa_ip_literal              = $params->{_marpa_ip_literal};
  my $_marpa_zoneid                  = $params->{_marpa_zoneid};
  my $_marpa_ipv4address             = $params->{_marpa_ipv4address};
  my $_marpa_reg_name                = $params->{_marpa_reg_name};
  #
  # From here, there should be NO access to $params except in variables referencing
  # grammar rules (because I wanted to left them with their angle brackets)
  #

  has $value         => (is => 'rwp', isa => Str,       required => 1, trigger => 1 );
  class_has $grammar => (is => 'ro',  isa => InstanceOf['Marpa::R2::Scanless:G'], default => sub { Marpa::R2::Scanless::G->new({ source => $BNF_section_data }) } );
  class_has $bnf     => (is => 'ro',  isa => Str,                                 default => sub { ${$BNF_section_data} } );
  has $scheme        => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $authority     => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $path          => (is => 'rw',  isa => Str,       default => sub {   ''  }); # There is always a path in an URI
  has $query         => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $fragment      => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $hier_part     => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $userinfo      => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $host          => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $port          => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $relative_part => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $ip_literal    => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $zoneid        => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $ipv4address   => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  has $reg_name      => (is => 'rw',  isa => Str|Undef, default => sub { undef });
  #
  # Normalization have specific rules on Path Segment and Protocol, not under our control, so we provide methods
  # to scheme specific attribute that a subclass should override.
  #
  has $scheme_normalization => (is => 'ro', isa => HashRef[CodeRef], default => sub { {}},
                                handles_via => 'Hash',
                                handles => {
                                            $_exists_scheme_normalization => 'exists',
                                            $_get_scheme_normalization => 'get',
                                           }
                               );
  #
  # Ditto for protocol
  #
  has $protocol_normalization => (is => 'ro', isa => HashRef[CodeRef], default => sub { {}},
                                  handles_via => 'Hash',
                                  handles => {
                                              $_exists_protocol_normalization => 'exists',
                                              $_get_protocol_normalization => 'get',
                                             }
                                 );

  method BUILD => sub {
    my ($self) = @_;
    $self->$_parse(0);
  };

  method BUILDARGS => sub {
    my ($class, @args) = @_;
    unshift(@args, $value) if (@args % 2 == 1);
    return { @args };
  };

  method $_trigger_value => sub {
    my ($self, $value) = @_;
    $self->$_parse(0);
  };

  method $canonical => sub {  # canonical is an on-demand parsing
    my ($self) = @_;
    ${$self->$_parse(1)};
  };

  method $is_absolute => sub {
    my ($self) = @_;
    #
    # No need to reparse. An absolute URI is when scheme and hier_part are defined,
    # and fragment is undefined
    #
    return Str->check($self->scheme) && Str->check($self->hier_part) && Undef->check($self->fragment);
  };

  method $_parse => sub {
    my ($self, $normalize) = @_;
    #
    # This hack just to avoid recursivity: we do not want Marpa to
    # call another new() but operate on our instance immediately
    #
    local $MooX::Role::ResourceIdentifier::SELF      = $self;
    local $MooX::Role::ResourceIdentifier::NORMALIZE = $normalize;
    $self->$grammar->parse(\$self->$value, { ranking_method => 'high_rule_only' });
  };

  method $_normalize => sub {
    my ($self, $normalized) = @_;

    my $rule_id = $Marpa::R2::Context::rule;
    my $slg     = $Marpa::R2::Context::slg;
    my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($rule_id);

    if ($lhs eq $params->{'<pct encoded>'}) {
      #
      # 6.2.2.1.  Case Normalization
      # ----------------------------
      # For all URIs, the hexadecimal digits within a percent-encoding
      # triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore
      # should be normalized to use uppercase letters for the digits A-F.
      #
      $normalized = uc($normalized);
      #
      # 6.2.2.2.  Percent-Encoding Normalization
      # ----------------------------------------
      # (These URIs) should be normalized by decoding any percent-encoded octet that corresponds
      # to an unreserved character, as described in Section 2.3.
      #
      # No need to call the grammar again, we know what they are:
      # <unreserved>    ::= ALPHA | DIGIT | [-._~]
      # ALPHA         ::= [A-Za-z]
      # DIGIT         ::= [0-9]
      #
      my $char = $normalized;
      substr($char, 0, 1, '');    # Remove the '%'
      $char = chr(hex($char));
      if ($char =~ /[A-Za-z0-9._~-]/) {
        $normalized = $char;
      }
    }
    elsif ($lhs eq $params->{'<path abempty>'}  ||
           $lhs eq $params->{'<path absolute>'} ||
           $lhs eq $params->{'<path noscheme>'} ||
           $lhs eq $params->{'<path rootless>'} ||
           $lhs eq $params->{'<path empty>'}) {
      #
      # 6.2.2.3.  Path Segment Normalization
      # ------------------------------------
      # URI normalizers should remove dot-segments by applying the
      # remove_dot_segments algorithm to the path
      #
      $normalized = $self->$_remove_dot_segments($normalized);
    }
    if ($self->$_exists_scheme_normalization($lhs)) {
      #
      # 6.2.3.  Scheme-Based Normalization
      #
      my $codeRef = $self->$_get_scheme_normalization($lhs);
      $normalized = $self->$codeRef($normalized);
    }
    if ($self->$_exists_protocol_normalization($lhs)) {
      #
      # 6.2.4.  Protocol-Based Normalization
      #
      my $codeRef = $self->$_get_protocol_normalization($lhs);
      $normalized = $self->$codeRef($normalized);
    }

    return $normalized;
  };

  method $_remove_dot_segments => sub {
    my ($self, $input) = @_;

    # my $rule_id = $Marpa::R2::Context::rule;
    # my $slg     = $Marpa::R2::Context::slg;
    # my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($rule_id);
    # print STDERR "$lhs ::= @rhs\n";

    #
    # 1.  The input buffer is initialized with the now-appended path
    # components and the output buffer is initialized to the empty
    # string.
    #
    my $output = '';

    # my $i = 0;
    # my $step = ++$i;
    # my $substep = '';
    # printf STDERR "%-10s %-30s %-30s\n", "STEP", "OUTPUT BUFFER", "INPUT BUFFER";
    # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
    # $step = ++$i;
    #
    # 2.  While the input buffer is not empty, loop as follows:
    #
    while (length($input)) {
      #
      # A. If the input buffer begins with a prefix of "../" or "./",
      #    then remove that prefix from the input buffer; otherwise,
      #
      if (index($input, '../') == 0) {
        substr($input, 0, 3, '');
        # $substep = 'A';
      }
      elsif (index($input, './') == 0) {
        substr($input, 0, 2, '');
        # $substep = 'A';
      }
      #
      # B. if the input buffer begins with a prefix of "/./" or "/.",
      #    where "." is a complete path segment, then replace that
      #    prefix with "/" in the input buffer; otherwise,
      #
      elsif (index($input, '/./') == 0) {
        substr($input, 0, 3, '/');
        # $substep = 'B';
      }
      elsif ($input =~ /^\/\.(?:[\/]|\z)/) {            # Take care this can confuse the other test on '/../ or '/..'
        substr($input, 0, 2, '/');
        # $substep = 'B';
      }
      #
      # C. if the input buffer begins with a prefix of "/../" or "/..",
      #    where ".." is a complete path segment, then replace that
      #    prefix with "/" in the input buffer and remove the last
      #    segment and its preceding "/" (if any) from the output
      #    buffer; otherwise,
      #
      elsif (index($input, '/../') == 0) {
        substr($input, 0, 4, '/');
        $output =~ s/\/?[^\/]*\z//;
        # $substep = 'C';
      }
      elsif ($input =~ /^\/\.\.(?:[^\/]|\z)/) {
        substr($input, 0, 3, '/');
        $output =~ s/\/?[^\/]*\z//;
        # $substep = 'C';
      }
      #
      # D. if the input buffer consists only of "." or "..", then remove
      #    that from the input buffer; otherwise,
      #
      elsif (($input eq '.') || ($input eq '..')) {
        $input = '';
        # $substep = 'D';
      }
      #
      # E. move the first path segment in the input buffer to the end of
      #    the output buffer, including the initial "/" character (if
      #    any) and any subsequent characters up to, but not including,
      #    the next "/" character or the end of the input buffer.
      #
      #    Note: "or the end of the input buffer" ?
      #
      else {
        $input =~ /^\/?([^\/]*)/;                            # This will always match
        $output .= substr($input, $-[0], $+[0] - $-[0], ''); # Note that perl has no problem saying length is zero
        # $substep = 'E';
      }
      # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
    }
    #
    # 3. Finally, the output buffer is returned as the result of
    #    remove_dot_segments.
    #
    return $output;
  };

  #
  # Grammar rules
  #
  method $_marpa_concat        => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; my $concat = join('', @_); return $MooX::Role::ResourceIdentifier::NORMALIZE ? $self->_normalize($concat) : $concat; };
  method $_marpa_scheme        => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$scheme        ($self->$_marpa_concat(@_)); };
  method $_marpa_authority     => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$authority     ($self->$_marpa_concat(@_)); };
  method $_marpa_path          => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$path          ($self->$_marpa_concat(@_)); };
  method $_marpa_query         => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$query         ($self->$_marpa_concat(@_)); };
  method $_marpa_fragment      => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$fragment      ($self->$_marpa_concat(@_)); };
  method $_marpa_hier_part     => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$hier_part     ($self->$_marpa_concat(@_)); };
  method $_marpa_userinfo      => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$userinfo      ($self->$_marpa_concat(@_)); };
  method $_marpa_host          => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$host          ($self->$_marpa_concat(@_)); };
  method $_marpa_port          => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$port          ($self->$_marpa_concat(@_)); };
  method $_marpa_relative_part => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$relative_part ($self->$_marpa_concat(@_)); };
  method $_marpa_ip_literal    => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$ip_literal    ($self->$_marpa_concat(@_)); };
  method $_marpa_zoneid        => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$zoneid        ($self->$_marpa_concat(@_)); };
  method $_marpa_ipv4address   => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$ipv4address   ($self->$_marpa_concat(@_)); };
  method $_marpa_reg_name      => sub { shift; my $self = $MooX::Role::ResourceIdentifier::SELF; return $self->$reg_name      ($self->$_marpa_concat(@_)); };

}

=head1 NOTES

The caller is required to use MooX::ClassAttribute.

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
