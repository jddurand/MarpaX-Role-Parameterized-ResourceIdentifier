use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Data::Dumper;
use Encode 2.21 qw/find_encoding encode decode/; # 2.21 for mime_name support
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types qw/Common Generic/;
use Moo::Role;
use MooX::Role::Logger;
use MooX::HandlesVia;
use MooX::Role::Parameterized;
use Role::Tiny;
use Scalar::Util qw/blessed/;
use Type::Params qw/compile/;
use Types::Encodings qw/Bytes/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Try::Tiny;

# -------------------------------------------
# The three structures we maintain internally
# -------------------------------------------
use constant {
  RAW                         =>  0,
  NORMALIZED                  =>  1,
  CONVERTED                   =>  2
};

# ------------------------
# The normalization ladder
# ------------------------
use constant {
  CASE_NORMALIZED             =>  0,
  CHARACTER_NORMALIZED        =>  1,
  PERCENT_ENCODING_NORMALIZED =>  2,
  PATH_SEGMENT_NORMALIZED     =>  3,
  SCHEME_BASED_NORMALIZED     =>  4,
  PROTOCOL_BASED_NORMALIZED   =>  5,

  _MAX_NORMALIZER             =>  5,
  _COUNT_NORMALIZER           =>  6
};
our @normalizer_names = qw/case_normalizer
                           character_normalizer
                           percent_encoding_normalizer
                           path_segment_normalizer
                           scheme_based_normalizer
                           protocol_based_normalizer/;

# ---------------------------------------------------
# The convertion ladder, currently there is only one
# and it is IRI->URI or URI->IRI depending on the
# "spec" attribute when doing the parameterized role
# ---------------------------------------------------
use constant {
  URI_CONVERTED              =>  0,
  IRI_CONVERTED              =>  1,

  _MAX_CONVERTER             =>  1,
  _COUNT_CONVERTER           =>  2
};
#
# Depending on the "spec" attribute we will call one
# converter only. If spec is "uri" we call conversion to iri.
# If spec is "iri" we call conversion to uri. Though there
# remains two possible converters:
#
our @converter_names = qw/uri_converter iri_converter/;

# -----
# Other
# -----
our @ucs_mime_name = map { find_encoding($_)->mime_name } qw/UTF-8 UTF-16 UTF-16BE UTF-16LE UTF-32 UTF-32BE UTF-32LE/;

# ------------------------------------------------------------
# Explicit slots for all supported attributes in input
# scheme is explicitely ignored, it is handled only by _top
# ------------------------------------------------------------
has input                   => ( is => 'rwp', isa => StringLike                            );
has has_recognized_scheme   => ( is => 'rw',  isa => Bool,        default => sub {   !!0 } );
has is_character_normalized => ( is => 'rwp', isa => Bool,        default => sub {   !!1 } );
#
# Implementations should 'around' the folllowings
#
has pct_encoded                     => ( is => 'ro',  isa => Str|Undef,   lazy => 1, builder => 'build_pct_encoded' );
has reserved                        => ( is => 'ro',  isa => RegexpRef,   lazy => 1, builder => 'build_reserved' );
has unreserved                      => ( is => 'ro',  isa => RegexpRef,   lazy => 1, builder => 'build_unreserved' );
has default_port                    => ( is => 'ro',  isa => Int|Undef,   lazy => 1, builder => 'build_default_port' );
has reg_name_convert_as_domain_name => ( is => 'ro',  isa => Bool,        lazy => 1, builder => 'build_reg_name_convert_as_domain_name' );
__PACKAGE__->_generate_attributes('normalizer', @normalizer_names);
__PACKAGE__->_generate_attributes('converter',  @converter_names);

# ------------------------------------------------------------------------------------------------
# Internal slots: one for the raw parse, one for the normalized value, one for the converted value
# ------------------------------------------------------------------------------------------------
has _structs                => ( is => 'rw',  isa => ArrayRef[Object] );
use constant {
  _RAW_STRUCT               =>  0,
  _NORMALIZED_STRUCT        =>  1,
  _CONVERTED_STRUCT         =>  2,

  _MAX_STRUCTS              =>  2,
  _COUNT_STRUCTS            =>  3
};
#
# Just a helper for me
#
has _indice_description     => ( is => 'ro',  isa => ArrayRef[Str], default => sub {
                                   [
                                    'Raw structure       ',
                                    'Normalized structure',
                                    'Converted structure '
                                   ]
                                 }
                               );
#
# Internally I use hash notation for performance
#
sub raw        { $_[0]->{_structs}->[0]->{$_[1] // 'output'} }
sub normalized { $_[0]->{_structs}->[1]->{$_[1] // 'output'} }
sub converted  { $_[0]->{_structs}->[2]->{$_[1] // 'output'} }

# -------------
# The overloads
# -------------
use overload (
              '""'     => sub { $_[0]->raw },
              '=='     => sub { $_[0]->normalized eq $_[1]->normalized },
              '!='     => sub { $_[0]->normalized ne $_[1]->normalized },
              fallback => 1,
             );

# =======================================================================
# We want parsing to happen immedately AFTER object was build and then at
# every input reconstruction
# =======================================================================
our $setup                = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
our $check_BUILDARGS      = compile(StringLike|HashRef);
our $check_BUILDARGS_Dict = compile(slurpy Dict[
                                                input                           => Optional[StringLike],
                                                octets                          => Optional[Bytes],
                                                encoding                        => Optional[Str],
                                                decode_strategy                 => Optional[Any],
                                                is_character_normalized         => Optional[Bool],
                                                reg_name_convert_as_domain_name => Optional[Bool]
                                               ]);
sub BUILDARGS {
  my ($class, $arg) = @_;

  my ($first_arg) = $check_BUILDARGS->($arg);

  my $input;
  my $is_character_normalized;

  my %args = ();

  if (StringLike->check($first_arg)) {
    $args{input} = "$first_arg";                        # Eventual stringification
  } else {
    my ($params) = $check_BUILDARGS_Dict->(%{$first_arg});
    %args = %{$params};

    croak 'Please specify either input or octets'                if (! exists($params->{input})  && ! exists($params->{octets}));
    croak 'Please specify only one of input or octets, not both' if (  exists($params->{input})  &&   exists($params->{octets}));
    croak 'Please specify encoding'                              if (  exists($params->{octets}) && ! exists($params->{encoding}));
    if (exists($params->{input})) {
      $args{input} = "$params->{input}";               # Eventual stringification
    } else {
      my $octets          = $params->{octets};
      my $encoding        = $params->{encoding};
      my $decode_strategy = $params->{decode_strategy} // Encode::FB_CROAK;
      if (! exists($params->{is_character_normalized})) {
        my $enc_mime_name = find_encoding($encoding)->mime_name;
        $args{is_character_normalized} = grep { $enc_mime_name eq $_ } @ucs_mime_name;
      }
      #
      # Encode::encode will croak by itself if decode_strategy is not ok
      #
      $args{input} = decode($encoding, $octets, $decode_strategy);
    }
  }

  if ($setup->uri_compat) {
    #
    # Copy from URI:
    # Get rid of potential wrapping
    #
    $args{input} =~ s/^<(?:URL:)?(.*)>$/$1/;
    $args{input} =~ s/^"(.*)"$/$1/;
    $args{input} =~ s/^\s+//;
    $args{input} =~ s/\s+$//;
  }

  \%args
}

sub BUILD {
  my ($self) = @_;
  #
  # Make sure we are calling the lazy builders. This is because
  # the parser is optimized by using explicit hash access to
  # $self
  #
  # Normalize
  #
  my $normalizer_wrapper_with_accessors = $self->_normalizer_wrapper_with_accessors;
  do { $normalizer_wrapper_with_accessors->[$_]->($self, '', '') } for 0.._MAX_NORMALIZER;
  #
  # Convert
  #
  my $converter_wrapper_with_accessors = $self->_converter_wrapper_with_accessors;
  my $_converter_indice = $self->_converter_indice;
  $converter_wrapper_with_accessors->[$_converter_indice]->($self, '', '');
  #
  # Parse the input
  #
  $self->_parse;
  #
  # And install an after modifier to automatically parse it again at every change
  #
  after input => sub { $self->_parse }
}
# =============================================================================
# Parameter validation
# =============================================================================
our $check_params = compile(
                            slurpy
                            Dict[
                                 whoami      => Str,
                                 type        => Enum[qw/common generic/],
                                 spec        => Enum[qw/uri iri/],
                                 bnf         => Str,
                                 reserved    => RegexpRef,
                                 unreserved  => RegexpRef,
                                 pct_encoded => Str|Undef,
                                 mapping     => HashRef[Str]
                                ]
                           );

# =============================================================================
# Parameterized role
# =============================================================================
#
# For Marpa optimisation
#
my %registrations = ();
my %context = ();

role {
  my $params = shift;
  #
  # -----------------------
  # Sanity checks on params
  # -----------------------
  my ($hash_ref)  = HashRef->($params);
  my ($PARAMS)    = $check_params->(%{$hash_ref});

  my $whoami      = $PARAMS->{whoami};
  my $type        = $PARAMS->{type};
  my $spec        = $PARAMS->{spec};
  my $bnf         = $PARAMS->{bnf};
  my $mapping     = $PARAMS->{mapping};

  #
  # Make sure $whoami package is doing MooX::Role::Logger is not already
  #
  Role::Tiny->apply_roles_to_package($whoami, 'MooX::Role::Logger') unless $whoami->DOES('MooX::Role::Logger');
  my $action_full_name = sprintf('%s::_action', $whoami);
  #
  # Push on-the-fly the action name
  # This will natively croak if the BNF would provide another hint for implementation
  #
  $bnf = ":default ::= action => $action_full_name\n$bnf";

  my $is_common   = $type eq 'common';
  #
  # A bnf package must provide correspondance between grammar symbols
  # and fields in a structure, in the form "<xxx>" => yyy.
  # The structure depend on the type: Common or Generic
  #
  my %fields = ();
  my $struct_new = $is_common ? Common->new : Generic->new;
  my $struct_class = blessed($struct_new);
  my @fields = $struct_new->FIELDS;
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
  my $marpa_trace_terminals = $setup->marpa_trace_terminals;
  my $marpa_trace_values    = $setup->marpa_trace_values;

  # -------
  # Logging
  # -------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "[$type] Cannot open trace filehandle, $!";
  local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package = $whoami;
  tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';

  my $converter_indice = $spec eq 'uri' ? IRI_CONVERTED : URI_CONVERTED;
  # ---------------------------------------------------------------------
  # This stub will be the one doing the real work, called by Marpa action
  # ---------------------------------------------------------------------
  #
  my %MAPPING = %{$mapping};
  my $args2array_sub = sub {
    my ($self, $criteria, @args) = @_;
    #
    # There are as many strings in output as there are structures
    #
    my @rc = (('') x _COUNT_STRUCTS);
    #
    # Concatenate
    #
    foreach my $istruct (0.._MAX_STRUCTS) {
      do { $rc[$istruct] .= ref($args[$_]) ? $args[$_]->[$istruct] : $args[$_] } for (0..$#args)
    }
    #
    # Normalize
    #
    do { $rc[_NORMALIZED_STRUCT] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper->[$_]->($self, $criteria, $rc[_NORMALIZED_STRUCT]) } for 0.._MAX_NORMALIZER;
    #
    # Convert
    #
    $rc[_CONVERTED_STRUCT] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper->[$converter_indice]->($self, $criteria, $rc[_CONVERTED_STRUCT]);

    \@rc
  };
  #
  # Parse method installed directly in the BNF package
  #
  my $grammar = Marpa::R2::Scanless::G->new({source => \$bnf});
  my %recognizer_option = (
                           trace_terminals   => $marpa_trace_terminals,
                           trace_values      => $marpa_trace_values,,
                           trace_file_handle => $trace_file_handle,
                           ranking_method    => 'high_rule_only',
                           grammar           => $grammar
                          );
  #
  # Marpa optimisation: we cache the registrations. At every recognizer's value() call
  # the actions are checked. But this is static information in our case
  #
  install_modifier($whoami, 'fresh', '_parse',
                   sub {
                     my ($self) = @_;

                     my $input = $self->input;

                     my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
                     #
                     # For performance reason, cache all $self-> accesses
                     #
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs           = $self->{_structs} = [map { $struct_class->new } 0.._MAX_STRUCTS];
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper = $self->{_normalizer_wrapper}; # Ditto
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper  = $self->{_converter_wrapper};  # This is why it is NOT lazy
                     #
                     # A very special case is the input itself, before the parsing
                     # We want to apply eventual normalizers and converters on it.
                     # To identify this special, $field and $lhs are both the
                     # empty string, i.e. a situation that can never happen during
                     # parsing
                     #
                     # Normalize
                     #
                     do { $input = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper->[$_]->($self, '', $input) } for 0.._MAX_NORMALIZER;
                     #
                     # Convert
                     #
                     $input = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper->[$converter_indice]->($self, '', $input);
                     #
                     # Parse (may croak)
                     #
                     $r->read(\$input);
                     croak "[$type] Parse of the input is ambiguous" if $r->ambiguous;
                     #
                     # Check result
                     #
                     # Marpa optimisation: we cache the registrations. At every recognizer's value() call
                     # the actions are checked. But this is static information in our case
                     #
                     my $registrations = $registrations{$whoami};
                     if (defined($registrations)) {
                       $r->registrations($registrations);
                     }
                     my $value_ref = $r->value($self);
                     if (! defined($registrations)) {
                       $registrations{$whoami} = $r->registrations();
                     }
                     my $value = ${$value_ref};
                     do { $self->{_structs}->[$_]->{output} = $value->[$_] } for 0.._MAX_STRUCTS;
                   }
                  );
  #
  # Inject the action
  #
  $context{$whoami} = {};
  install_modifier($whoami, 'fresh', '_action',
                   sub {
                     my ($self, @args) = @_;
                     my ($lhs, @rhs) = @{$context{$whoami}->{$Marpa::R2::Context::rule}
                                           //=
                                             do {
                                               my $slg = $Marpa::R2::Context::slg;
                                               my @rules = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                                               $rules[0] = "<$rules[0]>" if (substr($rules[0], 0, 1) ne '<');
                                               \@rules
                                             }
                                           };
                     my $field = $mapping->{$lhs};
                     my $criteria = $field || $lhs;
                     my $array_ref = $self->$args2array_sub($criteria, @args);
                     if (defined $field) {
                       #
                       # For performance reason, because we KNOW to what we are talking about
                       # we use explicit push() and set instead of the accessors
                       #
                       if ($field eq 'segments') {
                         #
                         # Segments is special
                         #
                         push(@{$MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->{segments}}, $array_ref->[$_]) for 0.._MAX_STRUCTS
                       } else {
                         $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->{$field} = $array_ref->[$_] for 0.._MAX_STRUCTS
                       }
                     }
                     $array_ref
                   }
                  );
  # -------------------------------------------------------
  # Generate the correct converter direction, used by BUILD
  # -------------------------------------------------------
  install_modifier($whoami, 'fresh', '_converter_indice' => sub { $converter_indice } );

  # ----------------------------------------------------
  # The builders that the implementation should 'around'
  # ----------------------------------------------------
  install_modifier($whoami, 'fresh', 'build_pct_encoded'              => sub { $PARAMS->{pct_encoded} });
  install_modifier($whoami, 'fresh', 'build_reserved'                 => sub {    $PARAMS->{reserved} });
  install_modifier($whoami, 'fresh', 'build_unreserved'               => sub {  $PARAMS->{unreserved} });
  install_modifier($whoami, 'fresh', 'build_is_character_normalized'  => sub {                    !!1 });
  install_modifier($whoami, 'fresh', 'build_default_port'             => sub {                  undef });
  install_modifier($whoami, 'fresh', 'build_reg_name_convert_as_domain_name'  => sub {                    !!0 });
  foreach (@normalizer_names, @converter_names) {
    install_modifier($whoami, 'fresh', "build_$_"                     => sub {              return {} });
  }
};
# =============================================================================
# Instance methods
# =============================================================================
sub abs {
  my ($self, $base) = @_;
  #
  # Do nothing if $self is already absolute
  #
  my $self_struct = $self->_structs->[_RAW_STRUCT];
  return $self if (defined $self_struct->{scheme});
  #
  # https://tools.ietf.org/html/rfc3986
  #
  # 5.2.1.  Pre-parse the Base URI
  #
  # The base URI (Base) is ./.. parsed into the five main components described in
  # Section 3.  Note that only the scheme component is required to be
  # present in a base URI; the other components may be empty or
  # undefined.  A component is undefined if its associated delimiter does
  # not appear in the URI reference; the path component is never
  # undefined, though it may be empty.
  #
  my $base_ri = (blessed($base) && $base->does(__PACKAGE__)) ? $base : blessed($self)->new($base);
  my $base_struct = $base_ri->{_structs}->[_RAW_STRUCT];
  #
  # This work only if $base is absolute and ($self, $base) support the generic syntax
  #
  croak "$base is not absolute"            unless defined $base_struct->{scheme};
  croak "$self must do the generic syntax" unless Generic->check($self_struct);
  croak "$base must do the generic syntax" unless Generic->check($base_struct);
  my %Base = (
              scheme    => $base_struct->{scheme},
              authority => $base_struct->{authority},
              path      => $base_struct->{path},
              query     => $base_struct->{query},
              fragment  => $base_struct->{fragment}
             );
  #
  #   Normalization of the base URI, as described in Sections 6.2.2 and
  # 6.2.3, is optional.  A URI reference must be transformed to its
  # target URI before it can be normalized.
  #
  # 5.2.2.  Transform References
  #
  #
  # -- The URI reference is parsed into the five URI components
  #
  #
  # --
  # (R.scheme, R.authority, R.path, R.query, R.fragment) = parse(R);
  #
  my %R = (
           scheme    => $self_struct->{scheme},
           authority => $self_struct->{authority},
           path      => $self_struct->{path},
           query     => $self_struct->{query},
           fragment  => $self_struct->{fragment}
          );
  #
  # -- A non-strict parser may ignore a scheme in the reference
  # -- if it is identical to the base URI's scheme.
  # --
  # if ((! $strict) && ($R{scheme} eq $Base{scheme})) {
  #   $R{scheme} = undef;
  # }
  my %T = ();
  if (defined  $R{scheme}) {
    $T{scheme}    = $R{scheme};
    $T{authority} = $R{authority};
    $T{path}      = __PACKAGE__->remove_dot_segments($R{path});
    $T{query}     = $R{query};
  } else {
    if (defined  $R{authority}) {
      $T{authority} = $R{authority};
      $T{path}      = __PACKAGE__->remove_dot_segments($R{path});
      $T{query}     = $R{query};
    } else {
      if (! length($R{path})) {
        $T{path} = $Base{path};
        $T{query} = Undef->check($R{query}) ? $Base{query} : $R{query}
      } else {
        if (substr($R{path}, 0, 1) eq '/') {
          $T{path} = __PACKAGE__->remove_dot_segments($R{path})
        } else {
          $T{path} = __PACKAGE__->_merge(\%Base, \%R);
          $T{path} = __PACKAGE__->remove_dot_segments($T{path});
        }
        $T{query} = $R{query};
      }
      $T{authority} = $Base{authority};
    }
    $T{scheme} = $Base{scheme};
  }

  $T{fragment} = $R{fragment};

  blessed($self)->new(__PACKAGE__->_recompose(\%T))
}
# =============================================================================
# Class methods
# =============================================================================
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
     join('',
          map {
            '%' . uc(unpack('H2', $_))
          } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK))
         )
    }
    !egp;
  $encoded
}

sub _merge {
  my ($class, $base, $ref) = @_;
  #
  # https://tools.ietf.org/html/rfc3986
  #
  # 5.2.3.  Merge Paths
  #
  # If the base URI has a defined authority component and an empty
  # path, then return a string consisting of "/" concatenated with the
  # reference's path; otherwise,
  #
  if (! Undef->check($base->{authority}) && ! length($base->{path})) {
    return '/' . $ref->{path};
  }
  #
  # return a string consisting of the reference's path component
  # appended to all but the last segment of the base URI's path (i.e.,
  # excluding any characters after the right-most "/" in the base URI
  # path, or excluding the entire base URI path if it does not contain
  # any "/" characters).
  #
  else {
    my $base_path = $base->{path};
    if ($base_path !~ /\//) {
      $base_path = '';
    } else {
      $base_path =~ s/\/[^\/]*\z/\//;
    }
    return $base_path . $ref->{path};
  }
}

sub _recompose {
  my ($class, $T) = @_;
  #
  # https://tools.ietf.org/html/rfc3986
  #
  # 5.3.  Component Recomposition
  #
  # We are called only by abs(), so we are sure to have a hash reference in argument
  #
  #
  my $result = '';
  $result .=        $T->{scheme} . ':' if (! Undef->check($T->{scheme}));
  $result .= '//' . $T->{authority}    if (! Undef->check($T->{authority}));
  $result .=        $T->{path};
  $result .= '?'  . $T->{query}        if (! Undef->check($T->{query}));
  $result .= '#'  . $T->{fragment}     if (! Undef->check($T->{fragment}));

  $result
}

sub remove_dot_segments {
  my ($class, $input) = @_;
  #
  # https://tools.ietf.org/html/rfc3986
  #
  # 5.2.4.  Remove Dot Segments
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
      substr($input, 0, 3, '')
      # $substep = 'A';
    }
    elsif (index($input, './') == 0) {
      substr($input, 0, 2, '')
      # $substep = 'A';
    }
    #
    # B. if the input buffer begins with a prefix of "/./" or "/.",
    #    where "." is a complete path segment, then replace that
    #    prefix with "/" in the input buffer; otherwise,
    #
    elsif (index($input, '/./') == 0) {
      substr($input, 0, 3, '/')
      # $substep = 'B';
    }
    elsif ($input =~ /^\/\.(?:[\/]|\z)/) {            # (?:[\/]|\z) means this is a complete path segment
      substr($input, 0, 2, '/')
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
      substr($input, 0, 4, '/'),
      $output =~ s/\/?[^\/]*\z//
      # $substep = 'C';
    }
    elsif ($input =~ /^\/\.\.(?:[\/]|\z)/) {          # (?:[\/]|\z) means this is a complete path segment
      substr($input, 0, 3, '/'),
      $output =~ s/\/?[^\/]*\z//
      # $substep = 'C';
    }
    #
    # D. if the input buffer consists only of "." or "..", then remove
    #    that from the input buffer; otherwise,
    #
    elsif (($input eq '.') || ($input eq '..')) {
      $input = ''
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
      $input =~ /^\/?([^\/]*)/,                           # This will always match
      $output .= substr($input, $-[0], $+[0] - $-[0], '') # Note that perl has no problem when $+[0] == $-[0], it will simply do nothing
      # $substep = 'E';
    }
    # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
  }
  #
  # 3. Finally, the output buffer is returned as the result of
  #    remove_dot_segments.
  #
  $output
}

sub unescape {
  my ($class, $value, $unreserved) = @_;

  my $unescaped_ok = 1;
  my $unescaped;
  try {
    my $octets = '';
    while ($value =~ m/(?<=%)[^%]+/gp) {
      $octets .= chr(hex(${^MATCH}))
    }
    $unescaped = MarpaX::RFC::RFC3629->new($octets)->output
  } catch {
    $unescaped_ok = 0;
    return
  };
  #
  # Keep only characters in the unreserved set
  #
  if ($unescaped_ok) {
    my $new_value = '';
    my $position_in_original_value = 0;
    my $reescaped_ok = 1;
    foreach (split('', $unescaped)) {
      my $reencoded_length;
      try {
        my $character = $_;
        my $reencoded = join('', map { '%' . uc(unpack('H2', $_)) } split(//, encode('UTF-8', $character, Encode::FB_CROAK)));
        $reencoded_length = length($reencoded);
      } catch {
        $reescaped_ok = 0;
      };
      last if (! $reescaped_ok);
      if ($_ =~ $unreserved) {
        $new_value .= $_;
      } else {
        $new_value = substr($value, $position_in_original_value, $reencoded_length);
      }
      $position_in_original_value += $reencoded_length;
    }
    $value = $new_value if ($reescaped_ok);
  }
  $value
}

# =============================================================================
# Internal class methods
# =============================================================================
sub _generate_attributes {
  my ($class, $type, @names) = @_;

  #
  # The lazy builders that implementation should around
  #
  foreach (@names) {
    my $builder = "build_$_";
    has $_ => (is => 'ro', isa => HashRef[CodeRef],
               lazy => 1,
               builder => $builder,
               handles_via => 'Hash',
               handles => {
                           "get_$_"    => 'get',
                           "set_$_"    => 'set',
                           "exists_$_" => 'exists',
                           "delete_$_" => 'delete',
                           "kv_$_"     => 'kv',
                           "keys_$_"   => 'keys',
                           "values_$_" => 'values',
                          }
              );
  }

  my $_type_names                  = "_${type}_names";
  my $_type_wrapper                = "_${type}_wrapper";
  my $_type_wrapper_with_accessors = "_${type}_wrapper_with_accessors";
  #
  # Just a convenient thing for us
  #
  has $_type_names   => (is => 'ro', isa => ArrayRef[Str|Undef], default => sub { \@names });
  #
  # The important thing is these wrappers:
  # - the one using accessors so that we are sure builders are executed
  # - the one without the accessors for performance
  #
  has $_type_wrapper => (is => 'ro', isa => ArrayRef[CodeRef|Undef],
                         # lazy => 1,                              Not lazy and this is INTENTIONAL
                         handles_via => 'Array',
                         handles => {
                                     "_get_$type" => 'get'
                                    },
                         default => sub {
                           $_[0]->_build_impl_sub(0, @names)
                         }
                        );
  has $_type_wrapper_with_accessors => (is => 'ro', isa => ArrayRef[CodeRef|Undef],
                                        # lazy => 1,                              Not lazy and this is INTENTIONAL
                                        handles_via => 'Array',
                                        handles => {
                                                    "_get_${type}_with_accessors" => 'get'
                                                   },
                                        default => sub {
                                          $_[0]->_build_impl_sub(1, @names)
                                        }
                                       );
}
# =============================================================================
# Internal instance methods
# =============================================================================
sub _build_impl_sub {
  my ($self, $call_builder, @names) = @_;

  my @array = ();
  foreach my $name (@names) {
    my $exists = "exists_$name";
    my $getter = "get_$name";
    #
    # We KNOW in advance that we are talking with a hash. So no need to
    # to do extra calls. The $exists and $getter variables are intended
    # for the outside world.
    # The inlined version using these accessors is:
    my $inlined_with_accessors = <<INLINED_WITH_ACCESSORS;
  # my (\$self, \$criteria, \$value) = \@_;
  #
  # This is intentionnaly doing NOTHING, but call the builders -;
  #
  \$_[0]->$exists(\$_[1])
INLINED_WITH_ACCESSORS
    # The inlined version using direct perl op is:
    my $inlined_without_accessors = <<INLINED_WITHOUT_ACCESSORS;
  # my (\$self, \$criteria, \$value) = \@_;
  #
  # At run-time, in particular Protocol-based normalizers,
  # the callbacks can be altered
  #
  exists(\$_[0]->{$name}->{\$_[1]}) ? goto \$_[0]->{$name}->{\$_[1]} : \$_[2]
INLINED_WITHOUT_ACCESSORS
    if ($call_builder) {
      push(@array,eval "sub {$inlined_with_accessors}")
    } else {
      push(@array,eval "sub {$inlined_without_accessors}")
    }
  }
  \@array
}

BEGIN {
  #
  # Marpa internal optimisation: we do not want the closures to be rechecked every time
  # we call $r->value(). This is a static information, although determined at run-time
  # the first time $r->value() is called on a recognizer.
  #
  no warnings 'redefine';

  sub Marpa::R2::Recognizer::registrations {
    my $recce = shift;
    if (@_) {
      my $hash = shift;
      if (! defined($hash) ||
          ref($hash) ne 'HASH' ||
          grep {! exists($hash->{$_})} qw/
                                           NULL_VALUES
                                           REGISTRATIONS
                                           CLOSURE_BY_SYMBOL_ID
                                           CLOSURE_BY_RULE_ID
                                           RESOLVE_PACKAGE
                                           RESOLVE_PACKAGE_SOURCE
                                           PER_PARSE_CONSTRUCTOR
                                         /) {
        Marpa::R2::exception(
                             "Attempt to reuse registrations failed:\n",
                             "  Registration data is not a hash containing all necessary keys:\n",
                             "  Got : " . ((ref($hash) eq 'HASH') ? join(', ', sort keys %{$hash}) : '') . "\n",
                             "  Want: CLOSURE_BY_RULE_ID, CLOSURE_BY_SYMBOL_ID, NULL_VALUES, PER_PARSE_CONSTRUCTOR, REGISTRATIONS, RESOLVE_PACKAGE, RESOLVE_PACKAGE_SOURCE\n"
                            );
      }
      $recce->[Marpa::R2::Internal::Recognizer::NULL_VALUES] = $hash->{NULL_VALUES};
      $recce->[Marpa::R2::Internal::Recognizer::REGISTRATIONS] = $hash->{REGISTRATIONS};
      $recce->[Marpa::R2::Internal::Recognizer::CLOSURE_BY_SYMBOL_ID] = $hash->{CLOSURE_BY_SYMBOL_ID};
      $recce->[Marpa::R2::Internal::Recognizer::CLOSURE_BY_RULE_ID] = $hash->{CLOSURE_BY_RULE_ID};
      $recce->[Marpa::R2::Internal::Recognizer::RESOLVE_PACKAGE] = $hash->{RESOLVE_PACKAGE};
      $recce->[Marpa::R2::Internal::Recognizer::RESOLVE_PACKAGE_SOURCE] = $hash->{RESOLVE_PACKAGE_SOURCE};
      $recce->[Marpa::R2::Internal::Recognizer::PER_PARSE_CONSTRUCTOR] = $hash->{PER_PARSE_CONSTRUCTOR};
    }
    return {
            NULL_VALUES            => $recce->[Marpa::R2::Internal::Recognizer::NULL_VALUES],
            REGISTRATIONS          => $recce->[Marpa::R2::Internal::Recognizer::REGISTRATIONS],
            CLOSURE_BY_SYMBOL_ID   => $recce->[Marpa::R2::Internal::Recognizer::CLOSURE_BY_SYMBOL_ID],
            CLOSURE_BY_RULE_ID     => $recce->[Marpa::R2::Internal::Recognizer::CLOSURE_BY_RULE_ID],
            RESOLVE_PACKAGE        => $recce->[Marpa::R2::Internal::Recognizer::RESOLVE_PACKAGE],
            RESOLVE_PACKAGE_SOURCE => $recce->[Marpa::R2::Internal::Recognizer::RESOLVE_PACKAGE_SOURCE],
            PER_PARSE_CONSTRUCTOR  => $recce->[Marpa::R2::Internal::Recognizer::PER_PARSE_CONSTRUCTOR]
           };
  } ## end sub registrations

  sub Marpa::R2::Scanless::R::registrations {
    my $slr = shift;
    my $thick_g1_recce =
      $slr->[Marpa::R2::Internal::Scanless::R::THICK_G1_RECCE];
    return $thick_g1_recce->registrations(@_);
  } ## end sub Marpa::R2::Scanless::R::registrations

}

1;
