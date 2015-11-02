use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

#
# This is a parameterized role because RFC3986 and RFC3987 share exactly the same
# implementation. The only difference is the grammar. This role will take a grammar
# as target package and generate the action, the internal structure and the required
# methods.
#

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Data::Dumper;
use Encode 2.21 qw/find_encoding encode/; # 2.21 for mime_name support
require UNIVERSAL::DOES unless defined &UNIVERSAL::DOES;
use Scalar::Does;
use Scalar::Util qw/blessed/;
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use MarpaX::Role::Parameterized::ResourceIdentifier::BUILD;
use MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Logger;
use Type::Params qw/compile/;
use Types::Standard -all;
use Try::Tiny;
use Role::Tiny;
use Unicode::Normalize qw/normalize/;
use constant {
  BNF_ROLE => 'MarpaX::Role::Parameterized::ResourceIdentifier::BNF',
  BUILD_ROLE => 'MarpaX::Role::Parameterized::ResourceIdentifier::BUILD',
  BUILDARGS_ROLE => 'MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS',
  LOGGER_ROLE => 'MooX::Role::Logger',
};
use constant {
  RAW                         =>  0,               # Concat: yes, Normalize: no,  Convert: no
  UNESCAPED                   =>  1,               # Concat: yes, Normalize: no,  Convert: no
  URI_CONVERTED               =>  2,               # Concat: yes, Normalize: no,  Convert: yes
  IRI_CONVERTED               =>  3,               # Concat: yes, Normalize: no,  Convert: yes
  CASE_NORMALIZED             =>  4,               # Concat: yes, Normalize: yes, Convert: no
  CHARACTER_NORMALIZED        =>  5,               # Concat: yes, Normalize: yes, Convert: no
  PERCENT_ENCODING_NORMALIZED =>  6,               # Concat: yes, Normalize: yes, Convert: no
  PATH_SEGMENT_NORMALIZED     =>  7,               # Concat: yes, Normalize: yes, Convert: no
  SCHEME_BASED_NORMALIZED     =>  8,               # Concat: yes, Normalize: yes, Convert: no
  ESCAPED                     =>  9,               # Concat: no,  Normalize: no,  Convert: no
  _COUNT                      => 10
};
use MooX::Role::Parameterized;

our $indice_concatenate_start = RAW;
our $indice_concatenate_end   = SCHEME_BASED_NORMALIZED;

our $indice_normalizer_start  = CASE_NORMALIZED;
our $indice_normalizer_end    = SCHEME_BASED_NORMALIZED;

our $indice_convertor_start   = URI_CONVERTED;
our $indice_convertor_end     = IRI_CONVERTED;

our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;
our $grammars = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;

use MooX::Struct -rw,
  _common => [ output         => [ isa => Str,           default => sub {    '' } ], # Parse tree value
               scheme         => [ isa => Str|Undef,     default => sub { undef } ],
               opaque         => [ isa => Str,           default => sub {    '' } ],
               fragment       => [ isa => Str|Undef,     default => sub { undef } ],
            ],
  _generic => [ -extends => ['_common'],
                hier_part     => [ isa => Str|Undef,     default => sub { undef } ],
                query         => [ isa => Str|Undef,     default => sub { undef } ],
                segment       => [ isa => Str|Undef,     default => sub { undef } ],
                authority     => [ isa => Str|Undef,     default => sub { undef } ],
                path          => [ isa => Str|Undef,     default => sub { undef } ],
                relative_ref  => [ isa => Str|Undef,     default => sub { undef } ],
                relative_part => [ isa => Str|Undef,     default => sub { undef } ],
                userinfo      => [ isa => Str|Undef,     default => sub { undef } ],
                host          => [ isa => Str|Undef,     default => sub { undef } ],
                port          => [ isa => Str|Undef,     default => sub { undef } ],
                ip_literal    => [ isa => Str|Undef,     default => sub { undef } ],
                ipv4_address  => [ isa => Str|Undef,     default => sub { undef } ],
                reg_name      => [ isa => Str|Undef,     default => sub { undef } ],
                ipv6_address  => [ isa => Str|Undef,     default => sub { undef } ],
                ipv6_addrz    => [ isa => Str|Undef,     default => sub { undef } ],
                ipvfuture     => [ isa => Str|Undef,     default => sub { undef } ],
                zoneid        => [ isa => Str|Undef,     default => sub { undef } ],
                segments      => [ isa => ArrayRef[Str], default => sub {  $setup->uri_compat ? [''] : [] } ],
              ];

# ==================================================================================
# Parameter validation
# ==================================================================================
our $check_params = compile(slurpy Dict[
                                        whoami      => Str,
                                        type        => Enum[qw/_common _generic/],
                                        bnf_package => Str,
                                        -extends    => Optional[ArrayRef[Str]]
                                       ]
                           );
our $check_bnf_package = compile(slurpy Dict[
                                             type        => Enum[qw/common generic/],
                                             reserved    => RegexpRef,
                                             unreserved  => RegexpRef,
                                             pct_encoded => Str,
                                             mapping     => HashRef[Str],
                                             action_name => Str
                                            ]
                                );

# ==================================================================================
# Common
# ==================================================================================
our @normalizer_name = qw/case_normalizer
                          character_normalizer
                          percent_encoding_normalizer
                          path_segment_normalizer
                          scheme_based_normalizer/;
our @convertor_name = qw/uri_convertor iri_convertor/;
our @ucs_mime_name = map { find_encoding($_)->mime_name } qw/UTF-8 UTF-16 UTF-16BE UTF-16LE UTF-32 UTF-32BE UTF-32LE/;

our %COMMON_ATTRIBUTES = (
                          _encoding               => [ is => 'ro',  isa => Str,  predicate => 1, trigger => 1],
                          is_character_normalized => [ is => 'rwp', isa => Bool, default => sub { !!1 }      ],
                          input                   => [ is => 'rwp', isa => Str                               ],
                          _structs                => [ is => 'rw',  isa => ArrayRef[Object]                  ]
                         );
do { $COMMON_ATTRIBUTES{$_} = [ is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => "build_$_" ] } for (@normalizer_name);
do { $COMMON_ATTRIBUTES{$_} = [ is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => "build_$_" ] } for (@convertor_name);
our %COMMON_METHODS = (
                       _trigger__encoding => sub {
                         my ($self, $_encoding) = @_;
                         #
                         # Remember if the octets were in an UCS-based encoding
                         #
                         my $enc_mime_name = find_encoding($_encoding)->mime_name;
                         $self->_set__is_character_normalized(grep { $enc_mime_name eq $_ } @ucs_mime_name);
                       },
                       is_absolute => sub {
                         my $raw = $_[0]->_structs->[RAW];
                         Str->check($raw->scheme) && $raw->can('hier_part') && Str->check($raw->hier_part)
                       }
                      );
do { $COMMON_METHODS{"build_$_"} = sub { return {} } } for (@normalizer_name);
do { $COMMON_METHODS{"build_$_"} = sub { return {} } } for (@convertor_name);

# ==================================================================================
# Generic
# ==================================================================================
our %GENERIC_ATTRIBUTES = (
                           is_reg_name_as_domain_name => [ is => 'ro', isa => Bool,     default => sub { !!0 } ],
                          );
our %GENERIC_METHODS = ();

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my ($hash_ref) = HashRef->($params);
  my ($PARAMS) = $check_params->(%{$hash_ref});

  my $whoami      = $PARAMS->{whoami};
  my $type        = $PARAMS->{type};
  my $bnf_package = $PARAMS->{bnf_package};
  my $extends     = $PARAMS->{-extends};

  my $is__common = $type eq '_common';
  my $is__generic = $type eq '_generic';

  use_module($bnf_package);
  #
  # Eventual extends should be done asap
  #
  if (defined $extends) {
    my $extends_sub;
    croak "[$type] $whoami must can extends (did you forgot to use Moo ?)" unless $extends_sub = $whoami->can('extends');
    &$extends_sub(@{$extends});
  }
  #
  # ----------------------------
  # Sanity checks on bnf_package
  # ----------------------------
  my $bnf_instance = $bnf_package->new();
  Role::Tiny->apply_roles_to_object($bnf_instance, BNF_ROLE) unless does($bnf_instance, BNF_ROLE);
  #
  # Make sure bnf instance really return what we want
  #
  my %BNF = ();
  map { $BNF{$_} = $bnf_instance->$_} qw/grammar bnf reserved unreserved pct_encoded mapping action_name/;
  croak "[$type] $bnf_package->grammar must do InstanceOf['Marpa::R2::Scanless::G']"  unless blessed($BNF{grammar}) && blessed($BNF{grammar}) eq 'Marpa::R2::Scanless::G';
  croak "[$type] $bnf_package->bnf must do Str"                    unless Str->check($BNF{bnf});
  croak "[$type] $bnf_package->reserved must do RegexpRef"         unless RegexpRef->check($BNF{reserved});
  croak "[$type] $bnf_package->unreserved must do RegexpRef"       unless RegexpRef->check($BNF{unreserved});
  croak "[$type] $bnf_package->pct_encoded must do Str|Undef"      unless Str->check($BNF{pct_encoded}) || Undef->check($BNF{pct_encoded});
  croak "[$type] $bnf_package->mapping must do Hashref[Str]"       unless HashRef->check($BNF{mapping}) && ! grep { ! Str->check($_) } keys %{$BNF{mapping}};
  croak "[$type] $bnf_package->pct_encoded must be like <...>'"    unless (! defined($BNF{pct_encoded})) || $BNF{pct_encoded} =~ /^<.*>$/;
  #
  # A bnf package must provide correspondance between grammar symbols and the fields in the structure
  # A field can appear more than once as a value, but its semantic is fixed by us.
  # A symbol must be like <...>
  #
  my %fields = ();
  my @fields = $is__common ? _common->FIELDS : _generic->FIELDS;
  map { $fields{$_} = 0 } @fields;
  foreach (keys %{$BNF{mapping}}) {
    my $field = $BNF{mapping}->{$_};
    croak "[$type] mapping $_ must be like <...>" unless $_ =~ /^<.*>$/;
    croak "[$type] mapping of $_ is unknown field: $field" unless exists $fields{$field};
    $fields{$field}++;
  }
  my @not_found = grep { ! $fields{$_} } keys %fields;
  croak "[$type] Unmapped fields: @not_found" unless ! @not_found;

  my $reserved    = $BNF{reserved};
  my $unreserved  = $BNF{unreserved};
  my $pct_encoded = $BNF{pct_encoded} // '';
  my $action_name = $BNF{action_name};
  my $reserved_or_unreserved = qr/(?:$reserved|$unreserved)/;
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
    local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package = $bnf_package;
    tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  }
  #
  # -------------------------------------
  # Helpers used internally, not exported
  # -------------------------------------
  my $_indice_description = sub {
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
  };
  my $max = _COUNT - 1;
  # -------------
  # Inlined stubs
  # -------------
  #
  # Normalizers
  #
  my @normalizer_sub = ();
  foreach (0..$max) {
    if (($_ < $indice_normalizer_start) || ($_ > $indice_normalizer_end)) {
      push(@normalizer_sub, undef) # No normalizer at this indice
    } else {
      my $name = $normalizer_name[$_ - $indice_normalizer_start];
      push(@normalizer_sub, sub {
             my $criteria = $_[1] || $_[3] || '';
             exists $_[0]->$name->{$criteria} ? $_[0]->$name->{$criteria}->(@_) : $_[2]
           }
          );
    }
  }
  #
  # Convertors
  #
  my @convertor_sub = ();
  foreach (0..$max) {
    if (($_ < $indice_convertor_start) || ($_ > $indice_convertor_end)) {
      push(@convertor_sub, undef) # No convertor at this indice
    } else {
      my $name = $convertor_name[$_ - $indice_normalizer_start];
      push(@convertor_sub, sub {
             my $criteria = $_[1] || $_[3] || '';
             exists $_[0]->$name->{$criteria} ? $_[0]->$name->{$criteria}->(@_) : $_[2]
           }
          );
    }
  }
  #
  # Marpa inner action
  #
  my %MAPPING = %{$BNF{mapping}};
  my $args2array_sub = sub {
    my ($self, $lhs, $field, @args) = @_;
    my $rc = [ ('') x _COUNT ];
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
            $self->_logger->warnf('%s: %s', $bnf_package, $_);
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
                    $self->_logger->warnf('%s: %s', $bnf_package, $_);
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
      do { $rc->[$inormalizer] = $normalizer_sub[$_]->($self, $field, $rc->[$inormalizer], $lhs) } for ($indice_normalizer_start..$inormalizer);
    }
    #
    # The convertors. Every entry may have its own converter.
    #
    foreach my $iconvertor ($indice_convertor_start..$indice_convertor_end) {
      #
      # For each converted value, we apply the previous convertors in order
      #
      $rc->[$iconvertor] = $convertor_sub[$iconvertor]->($self, $field, $rc->[$iconvertor], $lhs);
    }
    $rc
  };
  #
  # Input trigger
  #
  my %recognizer_option = (
                           trace_terminals =>  $marpa_trace_terminals,
                           trace_values =>  $marpa_trace_values,
                           ranking_method => 'high_rule_only',
                           grammar => $BNF{grammar}
                          );
  my $trigger_input = sub {
    my ($self, $input) = @_;

    my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
    $r->read(\$input);
    croak "[$type] Parse of the input is ambiguous" if $r->ambiguous;
    $self->_structs([map { $is__common ? _common->new : _generic->new } (0..$max)]);
    $r->value($self);
    if ($with_logger) {
      foreach (0..$max) {
        my $d = Data::Dumper->new([$self->_structs->[$_]->output], [$self->$_indice_description($_)]);
        $self->_logger->debugf('%s: %s', $bnf_package, $d->Dump);
      }
    }
  };
  # -----
  # Roles
  # -----
  if ($is__common) {
    #
    # Generic inherits from Common, so no need to install twice the role
    #
    BUILD_ROLE->apply({whoami => $whoami, input_attribute_name => 'input', input_trigger_name => '_trigger_input'}, target=> $whoami);
    BUILDARGS_ROLE->apply({whoami => $whoami, type => 'NotTop', second_argument => '_second_argument'}, target=> $whoami);
  }
  Role::Tiny->apply_roles_to_package($whoami, LOGGER_ROLE) unless $whoami->DOES(LOGGER_ROLE);
  #
  # ----------
  # Injections
  # ----------
  #
  my $has;
  croak "[$type] $whoami must have an 'has' method (did you forgot to load Moo ?)" unless CodeRef->check($has = $whoami->can('has'));
  my $around;
  croak "[$type] $whoami must have an 'around' method (did you forgot to load Moo ?)" unless CodeRef->check($around = $whoami->can('around'));
  if ($is__common) {

    do { &$has           (                   $_ => @{$COMMON_ATTRIBUTES{$_}}) } for keys %COMMON_ATTRIBUTES;
    do { install_modifier($whoami, 'fresh',  $_ =>   $COMMON_METHODS   {$_})  } for keys %COMMON_METHODS;

    install_modifier($whoami, 'fresh',  grammar       => sub { $BNF{grammar} });
    install_modifier($whoami, 'fresh',  bnf           => sub { $BNF{bnf} });
    install_modifier($whoami, 'fresh',  unreserved    => sub { $BNF{unreserved} });
    install_modifier($whoami, 'fresh', _trigger_input => $trigger_input );
  } else {

    do { &$has           (                   $_ => @{$GENERIC_ATTRIBUTES{$_}}) } for keys %GENERIC_ATTRIBUTES;
    do { install_modifier($whoami, 'fresh',  $_ =>   $GENERIC_METHODS   {$_})  } for keys %GENERIC_METHODS;

    &$around(grammar        => sub { $BNF{grammar} });
    &$around(bnf            => sub { $BNF{bnf} });
    &$around(unreserved     => sub { $BNF{unreserved} });
    &$around(_trigger_input => sub {
               my ($orig, $self, $input) = @_;
               try {
                 $self->$trigger_input($input);
               } catch {
                 if ($setup->uri_compat) {
                   if ($setup->with_logger) {
                     foreach (split(/\n/, "$_")) {
                       $self->_logger->tracef('%s: %s', $bnf_package, $_);
                     }
                   }
                   $self->$orig($input);
                 } else {
                   croak $_;
                 }
               }
             }
            );
  }
  #
  # For every inlined sub, the arguments are: ($self, $field, $value, $lhs) = @_
  #
  # This correspond to section:
  #
  # 5.3.2.  Syntax-Based Normalization
  #
  #
  if ($is__generic) {
    #
    # 5.3.2.1.  Case Normalization
    #
    &$around(
             build_case_normalizer => sub {
               return {
                       #
                       # For all IRIs, the hexadecimal digits within a percent-encoding
                       # triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore
                       # should be normalized to use uppercase letters for the digits A-F.
                       #
                       $pct_encoded => sub { uc($_[2]) },
                       #
                       # When an IRI uses components of the _generic syntax, the component
                       # syntax equivalence rules always apply; namely, that the scheme and
                       # US-ASCII only host are case insensitive and therefore should be
                       # normalized to lowercase.
                       #
                       scheme => sub { lc($_[2]) },
                       host   => sub { $_[2] =~ /[^\x{0}-\x{7F}]/ ? $_[2] : lc($_[2]) }
                      }
             }
            );
    #
    # 5.3.2.2.  Character Normalization
    #
    &$around(build_character_normalizer => sub {
               return {
                       #
                       # Equivalence of IRIs MUST rely on the assumption that IRIs are
                       # appropriately pre-character-normalized rather than apply character
                       # normalization when comparing two IRIs.  The exceptions are conversion
                       # from a non-digital form, and conversion from a non-UCS-based
                       # character encoding to a UCS-based character encoding. In these cases,
                       # NFC or a normalizing transcoder using NFC MUST be used for
                       # interoperability.
                       #
                       output => sub { $_[0]->is_character_normalized ? $_[2] : normalize('NFC', $_[2]) }
                      }
             }
            );
    #
    # 5.3.2.3.  Percent-Encoding Normalization
    #
    &$around(build_percent_encoding_normalizer => sub {
               return {
                       #
                       # ./.. IRIs should be normalized by decoding any
                       # percent-encoded octet sequence that corresponds to an unreserved
                       # character, as described in section 2.3 of [RFC3986].
                       #
                       $pct_encoded => sub {
                         my $normalized = $_[2];
                         try {
                           my $octets = '';
                           while ($normalized =~ m/(?<=%)[^%]+/gp) {
                             $octets .= chr(hex(${^MATCH}))
                           }
                           my $decoded = MarpaX::RFC::RFC3629->new($octets)->output;
                           $normalized = $decoded if $decoded =~ $unreserved;
                         };
                         $normalized
                       }
                      }
             }
            );
    #
    # 5.3.2.4.  Path Segment Normalization
    #
    &$around(build_path_segment_normalizer => sub {
               #
               # IRI normalizers should remove dot-segments by
               # applying the remove_dot_segments algorithm to the path, as described
               # in section 5.2.4 of [RFC3986]
               #
               return {
                       #
                       # Arguments: $self, $field, $value, $lhs
                       #
                       relative_part => sub { $_[0]->remove_dot_segments($_[2]) },
                       hier_part     => sub { $_[0]->remove_dot_segments($_[2]) }
                      }
             }
            );
  }
  #
  # This is installed in the BNF package, so there should never be a conflict
  #
  install_modifier($bnf_package, 'fresh', $action_name => sub {
                     my ($self, @args) = @_;
                     my $slg         = $Marpa::R2::Context::slg;
                     my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                     $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
                     my $field = $MAPPING{$lhs};
                     my $array_ref = &$args2array_sub($self, $lhs, $field, @args);
                     if ($with_logger) {
                       $self->_logger->tracef('%s: %s ::= %s', $bnf_package, $lhs, "@rhs");
                       $self->_logger->tracef('%s:   IN  %s', $bnf_package, \@args);
                       $self->_logger->tracef('%s:   OUT %s', $bnf_package, $array_ref);
                     }
                     my $structs = $self->_structs;
                     if (defined($field)) {
                       #
                       # Segments is special
                       #
                       if ($field eq 'segments') {
                         push(@{$structs->[$_]->segments}, $array_ref->[$_]) for (0..$max);
                       } else {
                         $structs->[$_]->$field($array_ref->[$_]) for (0..$max);
                       }
                     }
                     $array_ref
                   }
                  );
  #
  # For every structure field, we inject a method with an underscore in it
  # Optional indice is which version we want, defaulting to ESCAPED
  #
  foreach (@fields) {
    my $field = $_;
    my $name = "_$field";
    if (! $whoami->can($name)) {
      install_modifier($whoami, 'fresh', $name => sub { $_[0]->_structs->[$_[1] // ESCAPED]->$field });   # $self, $indice
    } else {
       &$around($name => sub { $_[1]->_structs->[$_[2] // ESCAPED]->$field });   # $orig, $self, $indice
    }
  }
};
#
# Instance methods common to any Resource Identifier
#
sub struct_by_type           { $_[0]->_structs->[$_[0]->indice($_[1])] }
sub output_by_type           { $_[0]->struct_by_type($_[1])->output }

sub struct_by_indice         { $_[0]->_structs->[$_[1]] }
sub output_by_indice         { $_[0]->struct_by_indice($_[1])->output }

sub recompose {
  my $scheme   = $_[0]->_scheme   // '';
  my $opaque   = $_[0]->_opaque   // '';
  my $fragment = $_[0]->_fragment // '';

  my $result = '';
  $result .= "$scheme:"   if (length($scheme));
  $result .= "$opaque"    if (length($opaque));
  $result .= "#$fragment" if (length($fragment));
  $result
}

#
# Class methods common to any Resource Identifier
#
sub indice_raw                         {                            RAW }
sub indice_unescaped                   {                      UNESCAPED }
sub indice_case_normalized             {                CASE_NORMALIZED }
sub indice_character_normalized        {           CHARACTER_NORMALIZED }
sub indice_percent_encoding_normalized {    PERCENT_ENCODING_NORMALIZED }
sub indice_path_segment_normalized     {        PATH_SEGMENT_NORMALIZED }
sub indice_escaped                     {                        ESCAPED }
sub indice_uri_converted               {                  URI_CONVERTED }
sub indice_iri_converted               {                  IRI_CONVERTED }
#
# The general normalized indice correspond to the latest of the normalizers
#
sub indice_default                     {               indice_escaped() }
sub indice_normalized                  {         $indice_normalizer_end }
sub indice {
  my ($class, $what) = @_;

  croak "Invalid undef argument" if (! defined($what));

  if    ($what eq 'RAW'                        ) { return RAW }
  elsif ($what eq 'UNESCAPED'                  ) { return UNESCAPED }
  elsif ($what eq 'CASE_NORMALIZED'            ) { return CASE_NORMALIZED }
  elsif ($what eq 'CHARACTER_NORMALIZED'       ) { return CHARACTER_NORMALIZED }
  elsif ($what eq 'PERCENT_ENCODING_NORMALIZED') { return PERCENT_ENCODING_NORMALIZED }
  elsif ($what eq 'PATH_SEGMENT_NORMALIZED'    ) { return PATH_SEGMENT_NORMALIZED }
  elsif ($what eq 'SCHEME_BASED_NORMALIZED'    ) { return SCHEME_BASED_NORMALIZED }
  elsif ($what eq 'ESCAPED'                    ) { return ESCAPED }
  elsif ($what eq 'URI_CONVERTED'              ) { return URI_CONVERTED }
  elsif ($what eq 'IRI_CONVERTED'              ) { return IRI_CONVERTED }
  else                                           { croak "Invalid argument $what"     }
}
sub percent_encode {
  my ($class, $string, $regexp) = @_;

  my $encoded = $string;
  $encoded =~ s!$regexp!
    {
     #
     # ${^MATCH} is a read-only variable
     # and Encode::encode is affecting $match -;
     #
     my $match = ${^MATCH};
     join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK)))
    }
    !egp;
  $encoded
}

sub remove_dot_segments {
  my ($class, $input) = @_;

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
}

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
