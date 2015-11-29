use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;

# ABSTRACT: Resource Identifier BNF role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode 2.21 qw/find_encoding encode decode/; # 2.21 for mime_name support
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
# use MarpaX::Role::Parameterized::ResourceIdentifier::Types qw/Common Generic/; # I moved to hash see below
use Module::Runtime qw/use_module/;
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

our $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;

# ---------------------------------------------------------------------------
# Structures for Common and Generic syntax
# My first implementation was using a MooX::Struct but I moved to an explicit
# hash for several reasons:
# - I do not need accessors inside the MooX::Struct
# - MooX::Struct->new() has a true cost -;
# ---------------------------------------------------------------------------
our $BLESS_COMMON  = sprintf('%s::%s', __PACKAGE__, '_common');
our $BLESS_GENERIC = sprintf('%s::%s', __PACKAGE__, '_generic');
sub _common_new {
  bless(
        {
         output   =>    '',
         scheme   => undef,
         opaque   =>    '',
         fragment => undef
        },
        $BLESS_COMMON
       )
}
sub _generic_new {
  bless(
        {
         output        => '',
         scheme        => undef,
         opaque        => '',
         fragment      => undef,
         hier_part     => undef,
         query         => undef,
         segment       => undef,
         authority     => undef,
         path          =>    '', # Never undef per construction
         relative_ref  => undef,
         relative_part => undef,
         userinfo      => undef,
         host          => undef,
         port          => undef,
         ip_literal    => undef,
         ipv4_address  => undef,
         reg_name      => undef,
         ipv6_address  => undef,
         ipv6_addrz    => undef,
         ipvfuture     => undef,
         zoneid        => undef,
         segments      => $setup->uri_compat ? [''] : []
        },
        $BLESS_GENERIC
       )
}
sub Generic_check { blessed($_[0]) eq $BLESS_GENERIC }

# -------------------------------------------
# The three structures we maintain internally
# -------------------------------------------
use constant {
  RAW                         =>  0,
  NORMALIZED                  =>  1,
  ESCAPED                     =>  2,
  CONVERTED                   =>  3
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
has secure                          => ( is => 'ro',  isa => Bool,        lazy => 1, builder => 'build_secure' );
has reg_name_convert_as_domain_name => ( is => 'ro',  isa => Bool,        lazy => 1, builder => 'build_reg_name_convert_as_domain_name' );
has current_location                => ( is => 'ro',  isa => Str|Undef,   lazy => 1, builder => 'build_current_location' );
has parent_location                 => ( is => 'ro',  isa => Str|Undef,   lazy => 1, builder => 'build_parent_location' );
__PACKAGE__->_generate_attributes('normalizer', @normalizer_names);
__PACKAGE__->_generate_attributes('converter',  @converter_names);

# ------------------------------------------------------------------------------------------------
# Internal slots: one for the raw parse, one for the normalized value, one for the converted value
# ------------------------------------------------------------------------------------------------
has _orig_arg               => ( is => 'rw',  isa => Any );   # For cloning
has _structs                => ( is => 'rw',  isa => ArrayRef[Object] );
use constant {
  _RAW_STRUCT               =>  0,
  _NORMALIZED_STRUCT        =>  1,
  _ESCAPED_STRUCT           =>  2,
  _CONVERTED_STRUCT         =>  3,

  _MAX_STRUCTS              =>  3,
  _COUNT_STRUCTS            =>  4
};
#
# Just a helper for me
#
has _indice_description     => ( is => 'ro',  isa => ArrayRef[Str], default => sub {
                                   [
                                    'Raw structure       ',
                                    'Normalized structure',
                                    'Escaped structure',
                                    'Converted structure '
                                   ]
                                 }
                               );
#
# Internally I use hash notation for performance
#
sub raw                 { $_[0]->{_structs}->[       _RAW_STRUCT]->{$_[1] // 'output'} }
sub normalized          { $_[0]->{_structs}->[_NORMALIZED_STRUCT]->{$_[1] // 'output'} }
sub escaped             { $_[0]->{_structs}->[   _ESCAPED_STRUCT]->{$_[1] // 'output'} }
sub converted           { $_[0]->{_structs}->[ _CONVERTED_STRUCT]->{$_[1] // 'output'} }
sub normalized_scheme   { $_[0]->{_structs}->[_NORMALIZED_STRUCT]->{'scheme'} }
sub normalized_opaque   { $_[0]->{_structs}->[_NORMALIZED_STRUCT]->{'opaque'} }
sub normalized_fragment { $_[0]->{_structs}->[_NORMALIZED_STRUCT]->{'fragment'} }
#
# Let's be always URI compatible for the canonical method
#
sub canonical  { goto &normalized }
#
# as_string returns the perl string
#
sub as_string  { goto &raw }

# =======================================================================
# We want parsing to happen immedately AFTER object was built and then at
# every input reconstruction
# =======================================================================
our $check_BUILDARGS      = compile(StringLike|HashRef);
our $check_BUILDARGS_Dict = compile(slurpy Dict[
                                                input                           => Optional[StringLike],
                                                octets                          => Optional[Bytes],
                                                encoding                        => Optional[Str],
                                                decode_strategy                 => Optional[Any],
                                                is_character_normalized         => Optional[Bool],
                                                reg_name_convert_as_domain_name => Optional[Bool],
                                                current_location                => Optional[Str],
                                                parent_location                 => Optional[Str]
                                               ]);
# -------------
# The overloads
# -------------
use overload (
              '""'     => sub { $_[0]->raw },
              '=='     => sub { $setup->uri_compat ?  _obj_eq(@_) : $_[0]->normalized eq $_[1]->normalized },
              '!='     => sub { $setup->uri_compat ? !_obj_eq(@_) : $_[0]->normalized ne $_[1]->normalized },
              fallback => 1,
             );

# Copy from URI
# Check if two objects are the same object
sub _obj_eq { overload::StrVal($_[0]) eq overload::StrVal($_[1]) }

sub BUILDARGS {
  my ($class, $arg) = @_;

  my ($first_arg) = $check_BUILDARGS->($arg);

  my $input;
  my $is_character_normalized;

  my %args = (_orig_arg => $first_arg);

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
  #
  # Normalize
  #
  my $normalizer_wrapper_call_lazy_builder = $self->_normalizer_wrapper_call_lazy_builder;
  do { $normalizer_wrapper_call_lazy_builder->[$_]->($self, '', '') } for 0.._MAX_NORMALIZER;
  #
  # Convert
  #
  my $converter_wrapper_call_lazy_builder = $self->_converter_wrapper_call_lazy_builder;
  my $_converter_indice = $self->_converter_indice;
  $converter_wrapper_call_lazy_builder->[$_converter_indice]->($self, '', '');
  #
  # Parse the input
  #
  $self->parse;
}
# =============================================================================
# Parameter validation
# =============================================================================
our $check_params = compile(
                            slurpy
                            Dict[
                                 whoami      => Str,
                                 type        => Enum[qw/_common _generic/],
                                 extends     => Optional[Str],
                                 spec        => Enum[qw/uri iri/],
                                 top         => Str,
                                 bnf         => Str,
                                 start       => Str,
                                 reserved    => RegexpRef,
                                 unreserved  => RegexpRef,
                                 pct_encoded => Str|Undef,
                                 mapping     => HashRef[Str],
                                 struct_ext  => Optional[CodeRef],
                                 _orig_arg   => Optional[Any]
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
  my $extends     = $PARAMS->{extends};
  my $struct_ext  = $PARAMS->{struct_ext};
  my $spec        = $PARAMS->{spec};
  my $top         = $PARAMS->{top};
  my $bnf         = $PARAMS->{bnf};
  my $mapping     = $PARAMS->{mapping};
  my $start       = $PARAMS->{start};
  my $unreserved  = $PARAMS->{unreserved};
  my $reserved    = $PARAMS->{reserved};
  my $pct_encoded = $PARAMS->{pct_encoded};
  my $reserved_or_unreserved = qr/(?:(?:$reserved)|(?:$unreserved))/;

  if ($extends) {
    #
    # An extension must provide 'can_scheme'
    #
    requires 'can_scheme';
  }

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

  #
  # Variable helpers
  #
  my $_RAW_STRUCT        = _RAW_STRUCT;
  my $_NORMALIZED_STRUCT = _NORMALIZED_STRUCT;
  my $_ESCAPED_STRUCT    = _ESCAPED_STRUCT;
  my $_CONVERTED_STRUCT  = _CONVERTED_STRUCT;
  my $_MAX_STRUCTS       = _MAX_STRUCTS;
  my $_MAX_NORMALIZER    = _MAX_NORMALIZER;
  my $is_common          = $type eq '_common';
  my $is_generic         = $type eq '_generic';
  #
  # A bnf package must provide correspondance between grammar symbols
  # and fields in a structure, in the form "<xxx>" => yyy.
  # The structure depend on the type: Common or Generic
  #
  my %fields = ();
  #
  # The version using Type:
  #
  #  my $struct_class = $is_common ? Common : Generic;
  #  my $struct_new = $struct_class->new;
  #  my @fields = $struct_new->FIELDS;
  #
  # The version using hashes:
  #
  my $struct_ctor = $is_common ? \&_common_new : \&_generic_new;
  #
  # If there is a struct_ext, this is a coderef that is amending
  # members to the structure. If undef, provide a default one
  # that is doing nothing
  #
  $struct_ext = sub { $_[0] } unless defined $struct_ext;
  my $struct_new = $struct_ext->(&$struct_ctor);

  my @fields = keys %{$struct_new};
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
  my @structures_for_concatenation = ($_RAW_STRUCT, $_NORMALIZED_STRUCT, $_CONVERTED_STRUCT);
  my %MAPPING = %{$mapping};
  my $args2array_sub = sub {
    my ($self, $criteria, @args) = @_;
    #
    # There are as many strings in output as there are structures
    #
    my @rc = (('') x _COUNT_STRUCTS);
    #
    # Concatenate. All structures but the escaped.
    #
    foreach my $istruct (@structures_for_concatenation) {
      do { $rc[$istruct] .= ref($args[$_]) ? $args[$_]->[$istruct] : $args[$_] } for (0..$#args)
    }
    #
    # Normalize
    #
    do { $rc[$_NORMALIZED_STRUCT] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper->[$_]->($self, $criteria, $rc[$_NORMALIZED_STRUCT]) } for 0..$_MAX_NORMALIZER;
    #
    # Convert: there is only one conversion, IRI -> URI or URI -> IRI
    #
    $rc[$_CONVERTED_STRUCT] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper->[$converter_indice]->($self, $criteria, $rc[$_CONVERTED_STRUCT]);
    #
    # Escape: if current rule is pct_encoded we keep the data as is, otherwise we escape. This is not configurable.
    #
    if (defined($pct_encoded) && ($criteria eq $pct_encoded)) {
      #
      # We say to percent_decode to accept not only unreserved characters, but also reserved characters.
      # Anything else will stay percent-encoded.
      #
      $rc[$_ESCAPED_STRUCT] = $self->percent_decode($rc[$_RAW_STRUCT], $reserved_or_unreserved)
    } else {
      #
      # Escape only what has not already been escaped
      #
      do { $rc[$_ESCAPED_STRUCT] .= ref($args[$_]) ? $args[$_]->[$_ESCAPED_STRUCT] : $self->escape($args[$_]) } for (0..$#args)
    }

    \@rc
  };
  #
  # Parse method installed directly in the BNF package
  #
  my $BNF = "inaccessible is ok by default\n:start ::= $start\n$bnf";
  my $grammar = Marpa::R2::Scanless::G->new({source => \$BNF});
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
  my $parse = sub {
    my ($self) = @_;

    my $input = $self->input;
    my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
    #
    # For performance reason, cache all $self-> accesses
    #
    # Version using Type:
    # local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs           = $self->{_structs} = [map { $struct_class->new } 0..$_MAX_STRUCTS];
    # Version using hashes:
    local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs           = $self->{_structs} = [map { $struct_ext->(&$struct_ctor) } 0..$_MAX_STRUCTS];
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
    do { $self->{_structs}->[$_]->{output} = $value->[$_] } for 0..$_MAX_STRUCTS;
    #
    # No return value from parse
    #
    return
  };
  install_modifier($whoami, 'fresh', parse => $parse);
  #
  # If this is an extension, then the parsing first call the extended implementation
  #
  my @all_fields = @fields;
  if ($extends) {
    my %all_fields = map { $_ => 1 } @all_fields;
    use_module($extends);
    foreach ($extends->__fields) {
      $all_fields{$_}++;
    }
    @all_fields = keys %all_fields;
    install_modifier($whoami, 'around', parse =>
                     sub {
                       my ($orig, $self) = (shift, shift);
                       #
                       # Call extended implementation
                       #
                       my $parent_self = $extends->new({input => $self->input});
                       #
                       # Get the _structs
                       #
                       my $parent_structs = $parent_self->{_structs};
                       #
                       # Call our method
                       #
                       $self->$orig(@_);
                       #
                       # And overwrite only the struct members
                       # that the extension declared
                       #
                       foreach my $index (0..$#{$parent_structs}) {
                         my $parent_struct = $parent_structs->[$index];
                         my $self_struct = $self->{_structs}->[$index];
                         foreach (keys %{$self_struct}) {
                           $parent_struct->{$_} = $self_struct->{$_} unless exists $parent_struct->{$_};
                         }
                         $self->{_structs}->[$index] = $parent_struct;
                       }
                     }
                    );
  }

  #
  # Inject the action
  #
  $context{$whoami} = {};
  install_modifier($whoami, 'fresh', _action =>
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
                         push(@{$MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->{segments}}, $array_ref->[$_]) for 0..$_MAX_STRUCTS
                       } else {
                         $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->{$field} = $array_ref->[$_] for 0..$_MAX_STRUCTS
                       }
                     }
                     $array_ref
                   }
                  );
  # -------------------------------------------------------
  # Generate the correct converter direction, used by BUILD
  # -------------------------------------------------------
  install_modifier($whoami, 'fresh', _converter_indice => sub { $converter_indice } );

  # ----------------------------------------------------
  # The builders that the implementation should 'around'
  # ----------------------------------------------------
  install_modifier($whoami, 'fresh', build_pct_encoded                     => sub { $PARAMS->{pct_encoded} });
  install_modifier($whoami, 'fresh', build_reserved                        => sub {    $PARAMS->{reserved} });
  install_modifier($whoami, 'fresh', build_unreserved                      => sub {  $PARAMS->{unreserved} });
  install_modifier($whoami, 'fresh', build_default_port                    => sub {                  undef });
  install_modifier($whoami, 'fresh', build_secure                          => sub {                    !!0 });
  install_modifier($whoami, 'fresh', build_reg_name_convert_as_domain_name => sub {                    !!0 });
  if ($is_common) {
    install_modifier($whoami, 'fresh', build_current_location              => sub {                  undef });
    install_modifier($whoami, 'fresh', build_parent_location               => sub {                  undef });
  } else {
    install_modifier($whoami, 'fresh', build_current_location              => sub {                    '.' });
    install_modifier($whoami, 'fresh', build_parent_location               => sub {                   '..' });
  }
  foreach (@normalizer_names, @converter_names) {
    install_modifier($whoami, 'fresh', "build_$_"                          => sub {              return {} });
  }
  # -------------------------------
  # Accessors to structures, fields
  # -------------------------------
  foreach (0..$_MAX_STRUCTS) {
    my $what;
    if    ($_ == 0) { $what = '_raw_struct'        }
    elsif ($_ == 1) { $what = '_normalized_struct' }
    elsif ($_ == 2) { $what = '_escaped_struct'    }
    elsif ($_ == 3) { $what = '_converted_struct'  }
    else            { croak 'Internal error'       }
    my $inlined = "\$_[0]->{_structs}->[$_]";
    install_modifier($whoami, 'fresh', $what => eval "sub { $inlined }" );
  }
  #
  # Normalized, escaped and converted structure contents should remain internal, not the raw struct
  #
  foreach (@all_fields) {
    my $inlined = "\$_[0]->{_structs}->[$_RAW_STRUCT]->{$_}";
    install_modifier($whoami, 'fresh', "_$_" => eval "sub { $inlined }" );
  }
  #
  # List of fields
  #
  install_modifier($whoami, 'fresh', __fields => sub { @all_fields } );
  #
  # All instance methods. Some of them could have been writen outside of this
  # parameterized role, though they might be a dependency on the $top variable
  # at any time in the development of this package. This is why all instance methods
  # are implemented here.
  #
  # remove_dot_segments: meaningful only for the generic syntax
  #
  if ($is_common) {
    install_modifier($whoami, 'fresh', remove_dot_segments => sub {
                       my ($self, $input, $remote_leading_dots) = @_;
                       $input
                     }
                    );
  } else {
    install_modifier($whoami, 'fresh', remove_dot_segments => sub {
                       my ($self, $input, $remote_leading_dots) = @_;
                       #
                       # https://tools.ietf.org/html/rfc3986
                       #
                       # 5.2.4.  Remove Dot Segments
                       #
                       # 1.  The input buffer is initialized with the now-appended path
                       # components and the output buffer is initialized to the empty
                       # string.
                       #
                       my $parent_location = $self->parent_location;
                       my $parent_location_RE = quotemeta($parent_location);
                       my $current_location = $self->current_location;

                       my $output = '';
                       my $remove_last_segment_in_output = sub {
                         if (length $output) {
                           #
                           # We do not remove last segment if it is already a '..'. This can happen only
                           # if we do not ignore leading dots
                           #
                           return 0 if (! $remote_leading_dots && $output =~ /(?:\A|\/)$parent_location_RE(?:\/|\z)/);
                           $output =~ s/\/?[^\/]*\/?\z// ? 1 : 0
                         } else {
                           0
                         }
                       };
                       my $process_parent_location = sub {
                         my $removed = &$remove_last_segment_in_output;
                         #
                         # when $_[0] is true, this mean there is a trailing '/'
                         #
                         if (! $remote_leading_dots & ! $removed) {
                           #
                           # If nothing was removed, it is in excess
                           #
                           if (length($output) && substr($output, -1, 1) eq '/') {
                             #
                             # Output already end with a '/'
                             #
                             $output .=       $parent_location;
                           } else {
                             $output .= '/' . $parent_location;
                           }
                           #
                           # Push the eventual trailing character
                           #
                           $output .= '/' if $_[0];
                         }
                       };
                       my $process_current_location = sub {
                         #
                         # when $_[0] is true, this mean there is a trailing '/'
                         #
                         if (! $remote_leading_dots) {
                           if (length($output)) {
                             if (substr($output, -1, 1) eq '/') {
                               #
                               # Output already end with a '/': no op regardless of $_[0]
                               #
                             } else {
                               #
                               # Output does not end with a '/': add '/' if $_[0]
                               #
                               $output .= '/' if $_[0];
                             }
                           } else {
                             #
                             # Output is empty: no op unless there is a trailing slash, i.e. '/./'
                             #
                             $output = '/' . $current_location . '/' if $_[0];
                           }
                         }
                       };
                       my $process_current_segment = sub {
                         #
                         # $_[0] contains the current segment
                         #
                         if (length($output) && substr($output, -1, 1) eq '/' && substr($_[0], 0, 1) eq '/') {
                           #
                           # segment start with a '/' and output already end with a '/'
                           #
                           substr($output, -1, 1, $_[0]);
                         } else {
                           $output .= $_[0];
                         }
                       };

                       # my $i = 0;
                       # my $step = ++$i;
                       # my $substep = '';
                       # printf STDERR "%-10s %-30s %-30s\n", "STEP", "OUTPUT BUFFER", "INPUT BUFFER (remote_leading_dots ? " . ($remote_leading_dots ? "yes" : "no") . ")";
                       # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
                       # $step = ++$i;
                       #
                       # 2.  While the input buffer is not empty, loop as follows:
                       #
                       my $A1 = $parent_location . '/';
                       my $A2 = $current_location . '/';

                       my $B1 = '/' . $current_location . '/';
                       my $B2 = '/' . $current_location;
                       my $B2_RE = quotemeta($B2);

                       my $C1 = '/' . $parent_location . '/';
                       my $C2 = '/' . $parent_location;
                       my $C2_RE = quotemeta($C2);

                       my $D1 = $current_location;
                       my $D2 = $parent_location;

                       while (length($input)) {
                         #
                         # A. If the input buffer begins with a prefix of "../" or "./",
                         #    then remove that prefix from the input buffer; otherwise,
                         #
                         if (index($input, $A1) == 0) {
                           # $substep = 'A1';
                           substr($input, 0, length($A1), ''), &$process_parent_location('/')
                         }
                         elsif (index($input, $A2) == 0) {
                           # $substep = 'A2';
                           substr($input, 0, length($A2), ''), &$process_current_location('/')
                         }
                         #
                         # B. if the input buffer begins with a prefix of "/./" or "/.",
                         #    where "." is a complete path segment, then replace that
                         #    prefix with "/" in the input buffer; otherwise,
                         #
                         elsif (index($input, $B1) == 0) {
                           # $substep = 'B1';
                           substr($input, 0, length($B1), '/'), &$process_current_location('/')
                         }
                         elsif ($input =~ /^$B2_RE(?:\/|\z)/) {            # (?:\/|\z) means this is a complete path segment
                           # $substep = 'B2';
                           substr($input, 0, length($B2), '/'), &$process_current_location
                         }
                         #
                         # C. if the input buffer begins with a prefix of "/../" or "/..",
                         #    where ".." is a complete path segment, then replace that
                         #    prefix with "/" in the input buffer and remove the last
                         #    segment and its preceding "/" (if any) from the output
                         #    buffer; otherwise,
                         #
                         elsif (index($input, $C1) == 0) {
                           # $substep = 'C1';
                           substr($input, 0, length($C1), '/'), &$process_parent_location('/')
                         }
                         elsif ($input =~ /^$C2_RE(?:\/|\z)/) {          # (?:\/|\z) means this is a complete path segment
                           # $substep = 'C2';
                           substr($input, 0, length($C2), '/'), &$process_parent_location
                         }
                         #
                         # D. if the input buffer consists only of "." or "..", then remove
                         #    that from the input buffer; otherwise,
                         #
                         elsif ($input eq $D1) {
                           # $substep = 'D1';
                           $input = '', &$process_current_location
                         }
                         elsif ($input eq $D2) {
                           # $substep = 'D2';
                           $input = '', &$process_parent_location
                         }
                         #
                         # E. move the first path segment in the input buffer to the end of
                         #    the output buffer, including the initial "/" character (if
                         #    any) and any subsequent characters up to, but not including,
                         #    the next "/" character or the end of the input buffer.
                         #
                         else {
                           # $substep = 'E';
                           #
                           # Notes:
                           # - the regexp always match
                           # - perl has no problem when $+[0] == $-[0], it will simply do nothing
                           #
                           $input =~ /^\/?([^\/]*)/, &$process_current_segment(substr($input, $-[0], $+[0] - $-[0], ''));
                         }
                         # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
                       }
                       #
                       # 3. Finally, the output buffer is returned as the result of
                       #    remove_dot_segments.
                       #
                       $output
                     }
                    )
  }


  #
  # rel(): too complicated to inline
  #
  install_modifier($whoami, 'fresh', rel =>
                   $is_common ?
                   #
                   # rel() on the common syntax is a no-op, we return $self
                   #
                   sub { $_[0] }
                   :
                   #
                   # rel() on the generic syntax. Totally based on URI algorithm
                   #
                   sub {
                     my ($self, $base, $rel_normalized) = @_;
                     croak 'Missing second argument' unless defined $base;

                     $rel_normalized //= $setup->rel_normalized;

                     #
                     # If already relative, do nothing
                     #
                     return $self if $self->is_relative;
                     #
                     # Make sure base is an object
                     #
                     my $base_ri = (blessed($base) && $base->InstanceOf($top)) ? $base : $top->new($base);
                     #
                     # Nothing to do if base is not absolute
                     #
                     return $self unless $base_ri->is_absolute;
                     #
                     # Nothing to do if self and base do not share the same notion of parent_location
                     #
                     return $self unless $self->parent_location eq $base_ri->parent_location;
                     #
                     # Get the raw and normalized results: normalized is used for all logical ops
                     #
                     my $self_struct  = $self->{_structs}->[$_RAW_STRUCT];                  # raw
                     my $nself_struct = $self->{_structs}->[$_NORMALIZED_STRUCT];           # normalized
                     my $wself_struct = $rel_normalized ? $nself_struct : $self_struct;     # work
                     my $base_struct  = $base_ri->{_structs}->[$_RAW_STRUCT];               # raw
                     my $nbase_struct = $base_ri->{_structs}->[$_NORMALIZED_STRUCT];        # normalized
                     my $wbase_struct = $rel_normalized ? $nbase_struct : $base_struct;     # work
                     #
                     # Nothing to do if neither self or base comply both with the generic syntax
                     #
                     return $self unless Generic_check($self_struct) && Generic_check($base_struct);
                     #
                     # Nothing to do if self and base do not share the same scheme
                     #
                     return $self unless ($wself_struct->{scheme} // '') eq ($wbase_struct->{scheme} // '');
                     #
                     # Ditto if they do not have the same (defined) authority
                     #
                     return $self unless (defined($wself_struct->{authority}) &&
                                          defined($wbase_struct->{authority}) &&
                                          $wself_struct->{authority} eq $wbase_struct->{authority});
                     #
                     # The algorithm is first on directories, derived from segments (for very last segment see below)
                     #
                     my @wself_dirs = @{$wself_struct->{segments}};
                     my @wbase_dirs = @{$wbase_struct->{segments}};
                     #
                     # Remember if self ends with a '/'
                     #
                     my $have_slash = @{$wself_struct->{segments}} && ! length($wself_struct->{segments}->[-1]);
                     #
                     # In uri_compat mode, first element is empty. This should always be the case, though we control that.
                     #
                     if ($setup->uri_compat) {
                       shift(@wself_dirs) if @wself_dirs && ! length $wself_dirs[0];
                       shift(@wbase_dirs) if @wbase_dirs && ! length $wbase_dirs[0];
                     }
                     #
                     # We want to have the equivalent of basename() on @wbase_dirs and @wself_dirs
                     # Query and eventual fragments are considered part of the basename
                     #
                     my $wself_basename = @wself_dirs ? (length($wself_dirs[-1]) ? pop(@wself_dirs) : undef) : undef;
                     my $wbase_basename = @wbase_dirs ? (length($wbase_dirs[-1]) ? pop(@wbase_dirs) : undef) : undef;
                     my ($wself_base, $wself_query, $wself_fragment) = ($wself_basename, $wself_struct->{query}, $wself_struct->{fragment});
                     my ($wbase_base, $wbase_query, $wbase_fragment) = ($wbase_basename, $wbase_struct->{query}, $wbase_struct->{fragment});
                     if (defined $wself_basename) {
                       $wself_basename .= '?' . $wself_query    if defined $wself_query;
                       $wself_basename .= '#' . $wself_fragment if defined $wself_fragment;
                     }
                     if (defined $wbase_basename) {
                       $wbase_basename .= '?' . $wbase_query    if defined $wbase_query;
                       $wbase_basename .= '#' . $wbase_fragment if defined $wbase_fragment;
                     }
                     #
                     # When a RI end with '/', its last segment is empty
                     #
                     pop(@wself_dirs) if (@wself_dirs && ! length($wself_dirs[-1]));
                     pop(@wbase_dirs) if (@wbase_dirs && ! length($wbase_dirs[-1]));
                     my $orig_nb_base_segments = scalar(@wbase_dirs);
                     #
                     # Now @wself_dirs and @wbase_dirs are guaranteed to contain only "dirname" parts
                     # We want to nuke @wself_dirs from what is is common with @wbase_dirs
                     #
                     while (@wself_dirs) {
                       last if (! @wbase_dirs);
                       last if ($wself_dirs[0] ne $wbase_dirs[0]);
                       shift @wself_dirs;
                       shift @wbase_dirs;
                     }
                     #
                     # If @wbase_dirs is not empty, its eventual base's basename, query and fragments are irrelevant.
                     # and any element in @base_segments is transformed to a parent location.
                     # But if it is empty, it is possible that there is equality.
                     #
                     my @parent_locations = map { $self->parent_location } 0..$#wbase_dirs;
                     if (! @parent_locations) {
                       #
                       # Same location !
                       # Do base and self share the same last segment ?
                       #
                       if (defined($wself_base) && defined($wbase_base) && $wself_base eq $wbase_base) {
                         #
                         # Yes: remove it from wself_basename
                         #
                         substr($wself_basename, 0, length($wself_base), '');
                         #
                         # Same query ?
                         #
                         if (defined($wself_query) && defined($wbase_query) && $wself_query eq $wbase_query) {
                           #
                           # Yes: remove it from wself_basename
                           #
                           substr($wself_basename, 0, 1 + length($wself_query), '');  # 1 because of the implicit '?'
                           #
                           # Same fragment ?
                           #
                           if (defined($wself_fragment) && defined($wbase_fragment) && $wself_fragment eq $wbase_fragment) {
                             #
                             # Yes: remove it from wself_basename
                             #
                             substr($wself_basename, 0, 1 + length($wself_fragment), '');  # 1 because of the implicit '#'
                           }
                         }
                       }
                     }
                     #
                     # Finally the relative URL is @parent_locations, @wself_dirs and eventual full $wself_basename
                     #
                     my $opaque = join('/', @parent_locations, @wself_dirs);
                     $opaque .= '/' if length $opaque;
                     if (defined $wself_basename) {
                       $opaque  .= $wself_basename;
                     } else {
                       #
                       # No basename: remove last '/' unless $self had one
                       #
                       substr($opaque, -1, 1, '') unless $have_slash;
                     }
                     if (! length $opaque) {
                       #
                       # Nothing: put at least current location and eventual slash
                       #
                       $opaque  = $self->current_location;
                       $opaque .= '/' if $have_slash;
                     }
                     my $rc = $top->new(__PACKAGE__->_recompose({opaque => $opaque}));
                     $rc
                   }
                  );
  #
  # abs(): ditto
  #
  install_modifier($whoami, 'fresh', abs =>
                   $is_common ?
                   #
                   # abs() on the common syntax is a no-op, we return $self
                   #
                   sub { $_[0] }
                   :
                   #
                   # abs() on the generic syntax is ok
                   #
                   sub {
                     my ($self, $base, $abs_normalized_base) = @_;
                     croak 'Missing second argument' unless defined $base;
                     $abs_normalized_base //= $setup->abs_normalized_base;

                     my $strict              = $setup->remove_dot_segments_strict;
                     my $remote_leading_dots = $setup->abs_remote_leading_dots;
                     #
                     # If reference is already absolute, nothing to do if we are in strict mode, or
                     # if self's base is not the same as absolute base
                     #
                     my $self_struct = $self->{_structs}->[$_RAW_STRUCT];
                     my $nself_struct = $self->{_structs}->[$_NORMALIZED_STRUCT];
                     my $base_ri;
                     my $base_struct;
                     my $nbase_struct;
                     if ($self->is_absolute) {
                       return $self if $strict;
                       $base_ri = (blessed($base) && $base->InstanceOf($top)) ? $base : $top->new($base);
                       $base_struct = $base_ri->{_structs}->[$_RAW_STRUCT];
                       $nbase_struct = $base_ri->{_structs}->[$_NORMALIZED_STRUCT];
                       #
                       # I suppose(d) that using the normalized scheme is implicit in this test
                       #
                       return $self unless $base_ri->is_absolute && ($nself_struct->{scheme} eq $nbase_struct->{scheme});
                     }
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
                     $base_ri //= (blessed($base) && $base->InstanceOf($top)) ? $base : $top->new($base);
                     #
                     # This is working only if $base is absolute
                     #
                     return $self unless $base_ri->is_absolute;
                     #
                     # The rest will work only if self and base share the same notions of
                     # current_location and parent_location
                     #
                     return $self unless
                       defined($self->current_location)    && defined($self->parent_location)    &&
                       defined($base_ri->current_location) && defined($base_ri->parent_location) &&
                       $self->current_location eq $base_ri->current_location                     &&
                       $self->parent_location  eq $base_ri->parent_location
                       ;
                     #
                     # Normalized version is used for all logical ops
                     #
                     $base_struct //= $base_ri->{_structs}->[$_RAW_STRUCT];
                     $nbase_struct //= $base_ri->{_structs}->[$_NORMALIZED_STRUCT];
                     #
                     # All structures have to comply with the generic syntax
                     #
                     return $self unless Generic_check($self_struct) && Generic_check($base_struct);
                     #
                     # Do the transformation
                     #
                     my %Base = (
                                 scheme    => $base_struct->{scheme},
                                 authority => $base_struct->{authority},
                                 path      => $base_struct->{path},
                                 query     => $base_struct->{query},
                                 fragment  => $base_struct->{fragment}
                                );
                     my %nBase = (
                                  scheme    => $nbase_struct->{scheme},
                                  authority => $nbase_struct->{authority},
                                  path      => $nbase_struct->{path},
                                  query     => $nbase_struct->{query},
                                  fragment  => $nbase_struct->{fragment}
                                 );
                     #
                     #   Normalization of the base URI, as described in Sections 6.2.2 and
                     # 6.2.3, is optional.  A URI reference must be transformed to its
                     # target URI before it can be normalized.
                     #
                     my %wBase = $abs_normalized_base ? %nBase : %Base;
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
                     my %nR = (
                               scheme    => $nself_struct->{scheme},
                               authority => $nself_struct->{authority},
                               path      => $nself_struct->{path},
                               query     => $nself_struct->{query},
                               fragment  => $nself_struct->{fragment}
                              );
                     #
                     # -- A non-strict parser may ignore a scheme in the reference
                     # -- if it is identical to the base URI's scheme.
                     # --
                     #
                     # I suppose(d) that using the normalized scheme is implicit here
                     #
                     if ((! $strict) && defined($nR{scheme}) && defined($nBase{scheme}) && ($nR{scheme} eq $nBase{scheme})) {
                       $R{scheme} = undef;
                     }
                     #
                     # Undef by default because it is the role of the method to apply what it think
                     # is the default
                     #
                     my %T = ();
                     if (defined $R{scheme}) {
                       $T{scheme}    = $R{scheme};
                       $T{authority} = $R{authority};
                       $T{path}      = $self->remove_dot_segments($R{path}, $remote_leading_dots);
                       $T{query}     = $R{query};
                     } else {
                       if (defined $R{authority}) {
                         $T{authority} = $R{authority};
                         $T{path}      = $self->remove_dot_segments($R{path}, $remote_leading_dots);
                         $T{query}     = $R{query};
                       } else {
                         if (! length($R{path})) {
                           $T{path} = $wBase{path};
                           $T{query} = Undef->check($R{query}) ? $wBase{query} : $R{query};
                         } else {
                           if (substr($R{path}, 0, 1) eq '/') {
                             $T{path} = $self->remove_dot_segments($R{path}, $remote_leading_dots);
                           } else {
                             $T{path} = __PACKAGE__->_merge(\%wBase, \%R);
                             $T{path} = $self->remove_dot_segments($T{path}, $remote_leading_dots);
                           }
                           $T{query} = $R{query};
                         }
                         $T{authority} = $wBase{authority};
                       }
                       $T{scheme} = $wBase{scheme};
                     }

                     $T{fragment} = $R{fragment};

                     $top->new(__PACKAGE__->_recompose(\%T))
                   }
                  );
  #
  # eq(): inlined and installed once only in the impl package
  #
  # eq is explicitly comparing canonical versions, where input does
  # not have to be an object (i.e. this is not using the overload)
  #
  my $eq_inlined = <<EQ;
use Types::Standard -all;
my (\$self, \$other) = \@_;
\$self  = $top->new(\$self)  unless blessed \$self;
\$other = $top->new(\$other) unless blessed \$other;
croak "\$self should inherit from $top" unless \$self->InstanceOf('$top');
croak "\$other should inherit from $top" unless \$other->InstanceOf('$top');
\$self->canonical eq \$other->canonical
EQ
  install_modifier($top, 'fresh', eq => eval "sub { $eq_inlined }") unless ($top->can('eq'));
  #
  # clone(): inlined
  #
  my $clone_inlined = <<CLONE;
$top->new(\$_[0]->{input})
CLONE
  install_modifier($whoami, 'fresh', clone => eval "sub { $clone_inlined }");
  #
  # is_absolute(): inlined
  #
  my $is_absolute_inlined = <<IS_ABSOLUTE;
my \$raw_struct = \$_[0]->{_structs}->[$_RAW_STRUCT];
defined \$raw_struct->{scheme}
IS_ABSOLUTE
  install_modifier($whoami, 'fresh', is_absolute => eval "sub { $is_absolute_inlined }");
  #
  # is_relative(): inlined
  #
  my $is_relative_inlined = <<IS_RELATIVE;
my \$raw_struct = \$_[0]->{_structs}->[$_RAW_STRUCT];
! defined \$raw_struct->{scheme}
IS_RELATIVE
  install_modifier($whoami, 'fresh', is_relative => eval "sub { $is_relative_inlined }");
  #
  # For all these fields, always apply the same algorithm.
  # Note that opaque field always has precedence overt authority or path or query
  #
  my @components = qw/scheme authority path query fragment opaque/;
  foreach my $component (@components) {
    #
    # Do it only if current structure support this component
    #
    # Version using Type:
    # next if ! $struct_new->can($component);
    # Version using hashes:
    next if ! grep { $_ eq $component} @all_fields;
    #
    # Fields used for recomposition are always limited to scheme+opaque+fragment if:
    # - current component is opaque, or
    # - current structure is common
    my @recompose_fields = (($component eq 'opaque') || $is_common) ? qw/scheme opaque fragment/ : qw/scheme authority path query fragment/;
    my $component_inlined = <<COMPONENT_INLINED;
my (\$self, \$argument) = \@_;
#
# Returned value is always the canonical form in uri compat mode, the raw value is non-uri compat mode
#
my \$struct    = \$MarpaX::Role::Parameterized::ResourceIdentifier::BNF::setup->uri_compat ? \$_[0]->_normalized_struct : \$_[0]->_raw_struct;
my \$value     = \$struct->{$component};
return \$value unless defined \$argument;
#
# Always reparse
#
my \%hash = ();
foreach (qw/@recompose_fields/) {
  \$hash{\$_} = (\$_ eq '$component') ? \$argument : \$struct->{\$_}
}
#
# Rebless and call us without argument
#
(\$_[0] = $top->new(\$self->_recompose(\\\%hash)))->$component
COMPONENT_INLINED
    install_modifier($whoami, 'fresh',  $component => eval "sub { $component_inlined }");
  }
  #
  # Some methods specific to the generic syntax as per original URI
  #
  if ($is_generic) {
    my $path_query_inlined = <<PATH_QUERY_INLINED;
my (\$self, \$argument) = \@_;
#
# Returned value is always the canonical form in uri compat mode, the raw value is non-uri compat mode
#
my \$struct    = \$MarpaX::Role::Parameterized::ResourceIdentifier::BNF::setup->uri_compat ? \$_[0]->_normalized_struct : \$_[0]->_raw_struct;
my \$value     = \$struct->{path};
\$value       .= '?' . \$struct->{query} if defined \$struct->{query};
return \$value unless defined \$argument;
#
# Always reparse
#
my (\$new_path, \$new_query) = (\$argument, undef);
if (\$argument =~ m/\\?/g) {
  my \$after_question_mark_pos = pos(\$argument);
  \$new_path  = substr(\$argument, 0, \$after_question_mark_pos - 1);
  \$new_query = substr(\$argument, \$after_question_mark_pos, length(\$argument) - \$after_question_mark_pos);
}
my \%hash = (
              scheme    => \$struct->{scheme},
              authority => \$struct->{authority},
              path      => \$new_path,
              query     => \$new_query,
              fragment  => \$struct->{fragment}
            );
#
# Rebless and call us without argument
#
(\$_[0] = $top->new(\$self->_recompose(\\\%hash)))->path_query
PATH_QUERY_INLINED
    install_modifier($whoami, 'fresh',  path_query => eval "sub { $path_query_inlined }");
  }
  #
  # Percent decoding, using the unreserved regexp from parameterized role,
  # though regexp can be given explicitely as a parameter.
  # This method must be used only on a percent-encoded string, and once only
  # in order to not percent-decode twice. This is why there is the pct_encoded
  # dependency in this parameterized role: the default is installing a callback
  # to percent_decode only when the LHS in pct_encoded.
  #
  install_modifier($whoami, 'fresh',  percent_decode =>
                   sub {
                     my ($self, $string, $unreserved_regexp) = @_;

                     $unreserved_regexp //= $unreserved;

                     my $unescaped_ok = 1;
                     my $unescaped;
                     try {
                       my $octets = '';
                       while ($string =~ m/(?<=%)[^%]+/gp) {
                         $octets .= chr(hex(${^MATCH}))
                       }
                       $unescaped = MarpaX::RFC::RFC3629->new($octets)->output
                     } catch {
                       $unescaped_ok = 0;
                       return
                     };
                     #
                     # Keep only characters in the unreserved_regexp set
                     #
                     if ($unescaped_ok) {
                       my $decoded_string = '';
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
                           return
                         };
                         last if (! $reescaped_ok);
                         if ($_ =~ $unreserved_regexp) {
                           $decoded_string .= $_;
                         } else {
                           $decoded_string = substr($string, $position_in_original_value, $reencoded_length);
                         }
                         $position_in_original_value += $reencoded_length;
                       }
                       $string = $decoded_string if ($reescaped_ok);
                     }
                     $string
                   }
                  );

  install_modifier($whoami, 'fresh', escape =>
                   sub {
                     my ($self, $string, $characters_to_keep) = @_;

                     $characters_to_keep //= $reserved_or_unreserved;
                     my $escaped = '';
                     foreach (split(//, $string)) {
                       #
                       # Characters to escape at those that are
                       # not part of the unreserved set nor the reserved characters
                       # reserved characters
                       if ($_ =~ $characters_to_keep) {
                         $escaped .= $_
                       } else {
                         my $match = $_;
                         try {
                           $escaped .=
                             join('',
                                  map {
                                    '%' . uc(unpack('H2', $_))
                                  } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK))
                                 )
                           } catch {
                             $escaped .= $match;
                             return;
                           };
                       }
                     }
                     $escaped
                   }
                  );

};

# =============================================================================
# Class methods
# =============================================================================
sub percent_encode {
  my ($class, $string, $regexp) = @_;

  $string =~ s!$regexp!
    {
     #
     # ${^MATCH} is a read-only variable
     # and Encode::encode is affecting $match -;
     #
     my $match = ${^MATCH};
     my $encoded;
     try {
       $encoded = join('',
                       map {
                         '%' . uc(unpack('H2', $_))
                       } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK))
                      )
     } catch {
       $encoded = $match;
       return;
     };
    }
    !egp;
  $string
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
  if (defined($base->{authority}) && ! length($base->{path})) {
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
  # We are compatiblee with both common and generic syntax:
  # - the common  case can have only scheme, path (== opaque) and fragment
  # - the generic case can have scheme, authority, path, query and fragment
  #
  my $result = '';
  $result .=        $T->{scheme} . ':' if (defined $T->{scheme});
  if (defined $T->{opaque}) {
    $result .=        $T->{opaque};
  } else {
    $result .= '//' . $T->{authority}    if (defined $T->{authority});
    $result .=        $T->{path};
    $result .= '?'  . $T->{query}        if (defined $T->{query});
  }
  $result .= '#'  . $T->{fragment}     if (defined $T->{fragment});

  $result
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

  my $_type_names                     = "_${type}_names";
  my $_type_wrapper                   = "_${type}_wrapper";
  my $_type_wrapper_call_lazy_builder = "_${type}_wrapper_call_lazy_builder";
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
  has $_type_wrapper_call_lazy_builder => (is => 'ro', isa => ArrayRef[CodeRef|Undef],
                                        # lazy => 1,                              Not lazy and this is INTENTIONAL
                                        handles_via => 'Array',
                                        handles => {
                                                    "_get_${type}_call_lazy_builder" => 'get'
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
    my $inlined_call_lazy_builder = <<INLINED_CALL_LAZY_BUILDER;
  # my (\$self, \$criteria, \$value) = \@_;
  #
  # This is intentionnaly doing NOTHING, but call the builders -;
  #
  \$_[0]->$exists(\$_[1])
INLINED_CALL_LAZY_BUILDER
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
      push(@array,eval "sub {$inlined_call_lazy_builder}")
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

#
# For re-use we require that the role parameters are all exported
#
requires 'role_params';
#
# Because we know exactly the format of role params, we can provide ourself
# a correct implementation of role params clone
#
sub role_params_clone {
  my ($class) = @_;

  my $params = $class->role_params;
  my %clone = %{$params};
  #
  # Everything is ok except mapping that shares a reference
  #
  my $mapping = $params->{mapping};
  $clone{mapping} = { map { $_ => $mapping->{$_} } (keys %{$mapping}) };

  \%clone
}

1;
