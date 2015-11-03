use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Data::Dumper;
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types qw/Common Generic/;
use Moo::Role;
use MooX::HandlesVia;
use MooX::Role::Parameterized;
use Type::Params qw/compile/;
use Types::Standard -all;
use Try::Tiny;
use constant {
  RAW                         =>  0, # Concat: yes, Normalize: no,  Convert: no
  UNESCAPED                   =>  1, # Concat: yes, Normalize: no,  Convert: no
  URI_CONVERTED               =>  2, # Concat: yes, Normalize: no,  Convert: yes
  IRI_CONVERTED               =>  3, # Concat: yes, Normalize: no,  Convert: yes
  CASE_NORMALIZED             =>  4, # Concat: yes, Normalize: yes, Convert: no
  CHARACTER_NORMALIZED        =>  5, # Concat: yes, Normalize: yes, Convert: no
  PERCENT_ENCODING_NORMALIZED =>  6, # Concat: yes, Normalize: yes, Convert: no
  PATH_SEGMENT_NORMALIZED     =>  7, # Concat: yes, Normalize: yes, Convert: no
  SCHEME_BASED_NORMALIZED     =>  8, # Concat: yes, Normalize: yes, Convert: no
  PROTOCOL_BASED_NORMALIZED   =>  9, # Concat: yes, Normalize: yes, Convert: no
  ESCAPED                     => 10, # Concat: no,  Normalize: no,  Convert: no
  _COUNT                      => 11
};
our $MAX   = _COUNT - 1;

#
# The data that will be parsed
# The result of the parsing, splitted into as many layers as supported
#
has _input                    => ( is => 'rw', isa => Str );
has _structs                  => ( is => 'rw', isa => ArrayRef[Object] );

# =============================================================================
# Concatenation: Semantics fixed inside this role
# =============================================================================
our $indice_concatenate_start    = RAW;
our $indice_concatenate_end      = PROTOCOL_BASED_NORMALIZED;

# =============================================================================
# Normalizers : Semantics left to the implementation
# =============================================================================
our $indice_normalizer_start     = CASE_NORMALIZED;
our $indice_normalizer_end       = PROTOCOL_BASED_NORMALIZED;
has case_normalizer              => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1,
                                     handles_via => 'Hash',
                                     handles => { get_case_normalizer => 'get' }
                                    );
has character_normalizer         => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
has percent_encoding_normalizer  => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
has path_segment_normalizer      => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
has scheme_based_normalizer      => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
has protocol_based_normalizer    => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
#
# Implementations should work around these builders
#
sub build_case_normalizer             { return {} }
sub build_character_normalizer        { return {} }
sub build_percent_encoding_normalizer { return {} }
sub build_path_segment_normalizer     { return {} }
sub build_scheme_based_normalizer     { return {} }
sub build_protocol_based_normalizer   { return {} }

has _normalizer_names            => (is => 'ro', isa => ArrayRef[Str], default => sub {
                                       [qw/
                                            case_normalizer
                                            character_normalizer
                                            percent_encoding_normalizer
                                            path_segment_normalizer
                                            scheme_based_normalizer
                                            protocol_based_normalizer
                                          /
                                       ]
                                     }
                                    );
has _normalizer_sub              => (is => 'ro', isa => ArrayRef[CodeRef], lazy => 1, builder => 1);

sub _build__normalizer_sub {
  $_[0]->_build_impl_sub($indice_normalizer_start, $indice_normalizer_end, $_[0]->_normalizer_names)
}

# =============================================================================
# Converters : implementation dependant
# =============================================================================
our $indice_converter_start      = URI_CONVERTED;
our $indice_converter_end        = IRI_CONVERTED;
has uri_converter                => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
has iri_converter                => (is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => 1);
#
# Implementations should work around these builders
#
sub build_uri_converter             { return {} }
sub build_iri_converter             { return {} }

has _converter_names             => (is => 'ro', isa => ArrayRef[Str], default => sub {
                                       [qw/
                                            uri_converter
                                            iri_converter
                                          /
                                       ]
                                     }
                                    );
has _converter_sub               => (is => 'ro', isa => ArrayRef[CodeRef], lazy => 1, builder => 1);

sub _build__converter_sub {
  $_[0]->_build_impl_sub($indice_normalizer_start, $indice_normalizer_end, $_[0]->_normalizer_names)
}


# =============================================================================
# Parameter validation
# =============================================================================
our $check = compile(
                     slurpy
                     Dict[
                          whoami      => Str,
                          type        => Enum[qw/common generic/],
                          bnf         => Str,
                          reserved    => RegexpRef,
                          unreserved  => RegexpRef,
                          pct_encoded => Str|Undef,
                          action_name => Str,
                          mapping     => HashRef[Str]
                         ]
                    );

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my ($hash_ref)  = HashRef->($params);
  # my ($PARAMS)    = $check->(%{$hash_ref});
  my $PARAMS = $params;

  my $whoami      = $PARAMS->{whoami};
  my $type        = $PARAMS->{type};
  my $bnf         = $PARAMS->{bnf};
  my $reserved    = $PARAMS->{reserved};
  my $unreserved  = $PARAMS->{unreserved};
  my $pct_encoded = $PARAMS->{pct_encoded} // '';
  my $mapping     = $PARAMS->{mapping};
  my $action_name = $PARAMS->{action_name};

  #
  # Replace on-the-fly the action name
  #
  $bnf =~ s/\$action/$action_name/;

  my $reserved_or_unreserved = qr/(?:$reserved|$unreserved)/;
  my $is_common   = $type eq 'common';
  my $is_generic  = $type eq 'generic';
  #
  # A bnf package must provide correspondance between grammar symbols
  # and fields in a structure, in the form "<xxx>" => yyy.
  # The structure depend on the type: Common or Generic
  #
  my %fields = ();
  my @fields = $is_common ? Common->new->FIELDS : Generic->new->FIELDS;
  map { $fields{$_} = 0 } @fields;
  while (my ($key, $value) = each %{$mapping}) {
    croak "[$type] symbol $key must be in the form <...>"
      unless $key =~ /^<.*>$/;
    croak "[$type] mapping of unknown field $value"
      unless exists $fields{$value};
    $fields{$value}++;
  }
  my @not_found = grep { ! $fields{$_} } keys %fields;
  croak "[$type] Unmapped fields: @not_found" unless ! @not_found;

  # -----
  # Setup
  # -----
  my $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
  my $marpa_trace_terminals = $setup->marpa_trace_terminals;
  my $marpa_trace_values    = $setup->marpa_trace_values;
  my $marpa_trace           = $setup->marpa_trace;
  my $with_logger           = $setup->with_logger;
  my $uri_compat            = $setup->uri_compat;

  #
  # -------
  # Logging
  # -------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "[$type] Cannot open trace filehandle, $!";
  if ($marpa_trace) {
    local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package = $whoami;
    tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  }
  # ---------------------------------------------------------------------
  # This stub will be the one doing the real work, called by Marpa action
  # ---------------------------------------------------------------------
  my %MAPPING = %{$mapping};
  my $args2array_sub = sub {
    my ($self, $lhs, $field, @args) = @_;
    my $rc = [ ('') x _COUNT ];
    #
    # Recuperate the adress once for all
    #
    state $whoami::normalizer_sub = $self->_normalizer_sub;
    state $whoami::converter_sub = $self->_converter_sub;
    #
    # Concatenate
    #
    foreach my $irc ($indice_concatenate_start..$indice_concatenate_end) {
      do { $rc->[$irc] .= ref($args[$_]) ? $args[$_]->[$irc] : $args[$_] } for (0..$#args)
    }
    #
    # Unescaped section - to be done only if this is a percent encoded rule
    #
    my $unescape_ok = 1;
    if ($lhs eq $pct_encoded) {
      try {
        my $octets = '';
        while ($rc->[RAW] =~ m/(?<=%)[^%]+/gp) {
          $octets .= chr(hex(${^MATCH}))
        }
        $rc->[UNESCAPED] = MarpaX::RFC::RFC3629->new($octets)->output
      } catch {
        if ($setup->with_logger) {
          foreach (split(/\n/, "$_")) {
            $self->_logger->warnf('%s: %s', $whoami, $_);
          }
        }
        $rc->[UNESCAPED] = $rc->[RAW];
        $unescape_ok = 0;
        return
      }
    }
    #
    # Escape section - this must be done only once.
    # We look to individual components, per def those not already escaped are the lexemes.
    # If a character is not in the reserved section, then everything explicitely not in the unreserved
    # section is escaped.
    #
    # We say character: this mean that when we try to encode, this is after the eventual decode.
    # We take care of one exception: when the lhs is <pct encoded> and the decoding failed.
    #
    if (! $unescape_ok) {
      #
      # Can happen only in a percent-encoded LHS. It failed. So we keep the section as it it,
      # just making sure it is uppercased to be compliant with the spec. Per def the percent-encoded
      # section contains only ASCII characters, so uc() is ok.
      #
      $rc->[ESCAPED] = uc($rc->[RAW])
    } else {
      #
      # If current LHS is <pct encoded>, then input is the decoded section, else the arguments
      #
      foreach ($lhs eq $pct_encoded ? $rc->[UNESCAPED] : @args) {
        if (ref) {
          #
          # This make sure a section is not escaped twice
          #
          $rc->[ESCAPED] .= $_->[ESCAPED]
        } else {
          #
          # This is a lexeme or a successully decoded <pct encoded> section
          #
          foreach (split '') {
            if ($_ =~ $reserved_or_unreserved) {
              $rc->[ESCAPED] .= $_
            } else {
              my $character = $_;
              try {
                $rc->[ESCAPED] .= do {
                  #
                  # This may croak
                  #
                  join('', map { '%' . uc(unpack('H2', $_)) } split(//, encode('UTF-8', $character, Encode::FB_CROAK)))
                }
              } catch {
                if ($setup->with_logger) {
                  foreach (split(/\n/, "$_")) {
                    $self->_logger->warnf('%s: %s', $whoami, $_);
                  }
                }
                $rc->[ESCAPED] .= $character
              }
            }
          }
        }
      }
    }
    #
    # The normalization ladder
    #
    foreach my $inormalizer ($indice_normalizer_start..$indice_normalizer_end) {
      #
      # For each normalized value, we apply the previous normalizers in order
      #
      do { $rc->[$inormalizer] = $whoami::normalizer_sub->[$_]->($self, $field, $rc->[$inormalizer], $lhs) } for ($indice_normalizer_start..$inormalizer);
    }
    #
    # The converters. Every entry may have its own converter.
    #
    foreach my $iconverter ($indice_converter_start..$indice_converter_end) {
      #
      # For each converted value, we apply the previous converters in order
      #
      $rc->[$iconverter] = $whoami::converter_sub->[$iconverter]->($self, $field, $rc->[$iconverter], $lhs);
    }
    $rc
  };
  #
  # Input trigger
  #
  my $grammar = Marpa::R2::Scanless::G->new({source => \$bnf});
  my %recognizer_option = (
                           trace_terminals =>  $marpa_trace_terminals,
                           trace_values    =>  $marpa_trace_values,
                           ranking_method  => 'high_rule_only',
                           grammar         => $grammar
                          );
  my $trigger_input = sub {
    my ($self, $input) = @_;

    my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
    $r->read(\$input);
    croak "[$type] Parse of the input is ambiguous" if $r->ambiguous;
    $self->_structs([map { $is_common ? Common->new : Generic->new } (0..$MAX)]);
    $r->value($self);
    if ($with_logger) {
      foreach (0..$MAX) {
        my $d = Data::Dumper->new([$self->_structs->[$_]->output], [$self->_indice_description($_)]);
        $self->_logger->debugf('%s: %s', $whoami, $d->Dump);
      }
    }
  };
  #
  # This is injected in the package, not in the role
  #
  install_modifier($whoami, 'fresh', bnf => sub { $bnf });
  install_modifier($whoami, 'fresh', grammar => sub { $grammar });
  install_modifier($whoami, 'fresh', $action_name => sub
                   {
                     my ($self, @args) = @_;
                     my $slg         = $Marpa::R2::Context::slg;
                     my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                     $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
                     my $field = $mapping->{$lhs};
                     my $array_ref = &$args2array_sub($self, $lhs, $field, @args);
                     if ($with_logger) {
                       $self->_logger->tracef('%s: %s ::= %s', $whoami, $lhs, "@rhs");
                       $self->_logger->tracef('%s:   IN  %s', $whoami, \@args);
                       $self->_logger->tracef('%s:   OUT %s', $whoami, $array_ref);
                     }
                     my $structs = $self->_structs;
                     if (defined($field)) {
                       #
                       # Segments is special
                       #
                       if ($field eq 'segments') {
                         push(@{$structs->[$_]->segments}, $array_ref->[$_]) for (0..$MAX);
                       } else {
                         $structs->[$_]->$field($array_ref->[$_]) for (0..$MAX);
                       }
                     }
                     $array_ref
                   }
                  );
};

sub _indice_description {
  # my ($self, $indice) = @_;
  return 'Invalid indice' if ! defined($_[1]);
  if    ($_[1] == RAW                        ) { return 'Raw value                        ' }
  elsif ($_[1] == UNESCAPED                  ) { return 'Unescaped value                  ' }
  elsif ($_[1] == CASE_NORMALIZED            ) { return 'Case normalized value            ' }
  elsif ($_[1] == CHARACTER_NORMALIZED       ) { return 'Character normalized value       ' }
  elsif ($_[1] == PERCENT_ENCODING_NORMALIZED) { return 'Percent encoding mormalized value' }
  elsif ($_[1] == PATH_SEGMENT_NORMALIZED    ) { return 'Path segment normalized value    ' }
  elsif ($_[1] == SCHEME_BASED_NORMALIZED    ) { return 'Scheme based normalized value    ' }
  elsif ($_[1] == ESCAPED                    ) { return 'Escaped value                    ' }
  elsif ($_[1] == URI_CONVERTED              ) { return 'URI converted value              ' }
  elsif ($_[1] == IRI_CONVERTED              ) { return 'IRI converted value              ' }
  else                                         { return 'Unknown indice                   ' }
}

sub _build_impl_sub {
  my ($self, $istart, $iend, $names) = @_;

  my @array = ( (undef) x _COUNT );
  foreach ($istart..$iend) {
    my $name = $self->$names->[$_];
    my $getter = "get_$name";
    $array[$_] = sub {
      # my ($self, $field, $value, $lhs) = @_;
      my $criteria = $_[1] || $_[3] || '';
      #
      # At run-time, in particular Protocol-based normalizers,
      # the callbacks can be altered
      #
      my $impl = $_[0]->$getter($criteria);
      defined($impl) ? goto &$impl : $_[2]
    }
  }
}

1;
